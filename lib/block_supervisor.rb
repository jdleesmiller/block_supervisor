require 'syscalls'

require 'block_supervisor/block_supervisor'
require 'block_supervisor/version'

class BlockSupervisor
  #
  # The child process exited normally.
  #
  ChildExited = Struct.new(:exit_code)

  #
  # The child process was terminated by a signal from somewhere else.
  #
  ChildSignaled = Struct.new(:signal)

  #
  # The child process made a disallowed system call ({#syscall_number}) and was
  # therefore killed.
  #
  ChildSyscallDisallowed = Struct.new(:syscall_number)

  def initialize
    @allowed_syscalls = Set[Syscalls::SYS_exit_group]
    @ignored_syscalls = Set.new
    @inherited_fds = Set[STDIN.fileno, STDOUT.fileno, STDERR.fileno]
    @close_other_fds = true
    @child_pre_trace = nil
    @parent_pre_trace = nil
    @resource_limits = []
    yield self if block_given?
  end 

  #
  # Set of syscalls that the child process is allowed to make (a whitelist). If
  # the child process makes a syscall that is not in this set or the
  # {#ignored_syscalls} set, it is terminated (see {ChildSyscallDisallowed}).
  #
  # Note that +SYS_exit_group+ is allowed by default, and it must be allowed.
  #
  # @return [Set<Integer>] not nil
  #
  attr_reader :allowed_syscalls 

  #
  # Set of syscalls that the child process can make, but which have no effect.
  # More precisely, they behave like <tt>return 0;</tt>.
  #
  # @return [Set<Integer>] not nil
  #
  attr_reader :ignored_syscalls 

  #
  # If {#close_other_fds} is true, only these file descriptors will be inherited
  # by the child process (but see notes for {#close_other_fds} for cautions and
  # advice on how to make sure this actually works).
  #
  # By default, the set contains the file descriptors for +STDIN+, +STDOUT+ and
  # +STDERR+.
  #
  # Note that this is separate from the +FD_CLOEXEC+ flag. If the child process
  # calls +exec+, any FDs that the parent opened with +FD_CLOEXEC+ will not be
  # open after the +exec+, regardless of whether they're in this list.
  #
  # @return [Set<Integer>] not nil
  #
  attr_reader :inherited_fds 

  #
  # Before running the supervised block, close any file descriptors not in the
  # {#inherited_fds} set; the default is +true+.
  #
  # To do this, we have to close all of the other file descriptors. Linux does
  # not seem to help us very much here; see
  # http://stackoverflow.com/questions/899038/getting-the-highest-allocated-file-descriptor
  # and the discussion for the geordi bot (in EvalCxx.hsc).
  #
  # The approach we take here is to try to close all file descriptors that are
  # less than (the soft limit for) +RLIMIT_NOFILE+ and not in {#inherited_fds}.
  # This is not perfect. If you open lots of files and then lower
  # +RLIMIT_NOFILE+, some FDs may remain open and accessible to the child. To
  # avoid this, the approach used by geordi is to set +RLIMIT_NOFILE+ to a
  # sensible number immediately upon starting the (parent) program. The default
  # +RLIMIT_NOFILE+ seems to be 1024, so this does go through quite a few FDs.
  #
  attr_accessor :close_other_fds

  #
  # Call the given block from the child process before ptracing, and before
  # running the supervised block. This is intended to allow you to impose any
  # restrictions on the child process that are not exposed by this class.
  #
  # If this is called multiple times, the blocks are nested (later calls happen
  # first).
  #
  def child_pre_trace
    old_child_pre_trace = @child_pre_trace
    @child_pre_trace = proc {
      yield
      old_child_pre_trace.call if old_child_pre_trace
    }
  end

  #
  # Call the given block from the parent process before starting to ptrace the
  # child. This complements {#child_pre_trace}.
  #
  # If this is called multiple times, the blocks are nested (later calls happen
  # first).
  #
  def parent_pre_trace &block
    old_parent_pre_trace = @parent_pre_trace
    @parent_pre_trace = proc {
      yield
      old_parent_pre_trace.call if old_parent_pre_trace
    }
  end

  #
  # Add the given syscalls to {#allowed_syscalls}.
  #
  # @return [nil]
  #
  def allow_syscalls *syscall_numbers
    @allowed_syscalls.merge(syscall_numbers)
    nil
  end

  #
  # Add the given syscalls to {#ignored_syscalls}.
  #
  # @return [nil]
  #
  def ignore_syscalls *syscall_numbers
    @ignored_syscalls.merge(syscall_numbers)
    nil
  end

  #
  # Add the given file descriptors to {#inherited_fds}.
  #
  # @return [nil]
  #
  def inherit_fds *fds
    @inherited_fds.merge(fds)
    nil
  end

  #
  # @param [Fixnum] syscall_number syscall number (e.g. {Syscalls.SYS_open})
  #
  # @return [Boolean] true iff the given syscall is in {#allowed_syscalls}
  #
  def syscall_allowed? syscall_number
    @allowed_syscalls.member?(syscall_number)
  end

  #
  # @param [Fixnum] syscall_number syscall number (e.g. {Syscalls.SYS_open})
  #
  # @return [Boolean] true iff the given syscall is in {#ignored_syscalls}
  #
  def syscall_ignored? syscall_number
    @ignored_syscalls.member?(syscall_number)
  end

  #
  # @param [Fixnum] fd file descriptor (e.g. 1 for stdout)
  #
  # @return [Boolean] true iff the given file descriptor is in {#inherited_fds}
  #
  def fd_inherited? fd
    @inherited_fds.member?(fd)
  end

  #
  # Set resource limits on the child process. This just saves the parameters
  # and later calls the built in <tt>Process.setrlimit</tt> methods from the
  # child process.
  #
  # @param [String, Symbol] resource passed on to <tt>Process.setrlimit</tt> in
  #        the child process
  #
  # @param [Number] soft_limit passed on to <tt>Process.setrlimit</tt> in the
  #        child process
  #
  # @param [Number] hard_limit passed on to <tt>Process.setrlimit</tt> in the
  #        child process
  #
  # @return [nil]
  #
  def setrlimit resource, soft_limit, hard_limit=soft_limit
    @resource_limits << [resource, soft_limit, hard_limit]
    nil
  end

  #
  # Run a command using <tt>Kernel.exec</tt> with the configured limits.
  #
  def supervise_exec *args
    supervise { Kernel.exec(*args) }
  end

  #
  # Run the given block in a child process under ptrace. The system calls that
  # it makes are monitored, and if it makes a system call that is not allowed or
  # ignored, the child process is killed.
  #
  # You may want to call <tt>Kernel.exit!</tt> at the end of the block to
  # prevent any +at_exit+ handlers set on the parent process from running in
  # the child process as well.
  #
  # This method does not capture any output from the child process; the child
  # process just inherits the stdin, stdout and stderr of the parent (along with
  # any other open file handles). See also {#capture}.
  #
  # @return [ChildExited, ChildSignaled, ChildSyscallDisallowed]
  #
  def supervise
    raise "supervise must be given a block" unless block_given?

    child_pid = fork {
      # prevent file descriptors from being inherited, if requested
      child_close_other_fds if close_other_fds 

      # TODO apply resource limits

      # give the caller a chance to get in before tracing
      @child_pre_trace.call if @child_pre_trace

      # call into native code to start tracing
      child_trace

      # we are now being ptraced; run the caller's block
      yield
    }

    # give the caller a chance to get in before tracing
    @parent_pre_trace.call if @parent_pre_trace

    # call into native tracing code for the parent
    parent_trace(child_pid)
  end
  
  #
  # Run the given block in a child process under ptrace (like {#supervise}), and
  # capture the standard out and standard error streams.
  #
  # Note that this function can't currently handle large amounts of output: it's
  # limited by the pipe buffer size. If the child tries to write more than the
  # pipe buffer size, it will hang. This will hopefully be fixed in the future
  # (need separate threads for tracing and reading).
  #
  # @return [result, stdout, stderr] result is one of the return codes from
  #         {#supervise}; stdout is the captured stdout output of the child as a
  #         string; stderr is the captured stderr output of the child as a
  #         string
  def capture
    raise "capture must be given a block" unless block_given?

    # create pipes so we can redirect output streams
    out_r, out_w = IO.pipe
    err_r, err_w = IO.pipe

    # the child should NOT close the write ends of the pipes, but it should
    # close the read ends; we don't want to leak these fds, so keep original set
    old_inherited_fds = @inherited_fds.dup
    inherit_fds(*[out_w, err_w].map(&:fileno))
    
    # use the pre_trace handlers to set up the pipes on the child...
    child_pre_trace do
      # redirect stdout and stderr before tracing
      $stdout.reopen(out_w)
      $stderr.reopen(err_w)
    end

    # ... and the parent
    parent_pre_trace do
      # close the child end of the pipes from the parent
      [out_w, err_w].each(&:close)
    end

    begin
      result = supervise {
        # now we are being traced
        begin
          yield
        ensure
          [out_w, err_w].each(&:close)
        end
      }

      # read from output from pipes once we finish tracing; this means that
      # the output is limited by the pipe buffer size
      [result, out_r.read, err_r.read]
    ensure
      [out_r, err_r].each(&:close)

      # forget about the FDs we added above
      @inherited_fds = old_inherited_fds
    end
  end

#  def spawn *args
#    supervise {
#      spawn_pid = Process.spawn(*args)
#      Process.wait(spawn_pid)
#      exit! $?.exitstatus
#    }
#  end

  private

  #
  # See {#close_other_fds}.
  #
  def child_close_other_fds
    # close everything up to RLIMIT_NOFILE
    hi_fd, hi_fd_hard = Process.getrlimit(:NOFILE)
    raise "RLIMIT_NOFILE is negative" if hi_fd < 0

    # call into native code to actually close the fds
    child_close_fds(hi_fd)
  end
end

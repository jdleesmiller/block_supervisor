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
    yield self if block_given?
  end 

  #
  # Set of syscalls that the child process is allowed to make (a whitelist). If
  # the child process makes a syscall that is not in this set or the
  # {#ignored_syscalls} set, it is terminated (see {ChildSyscallDisallowed}).
  #
  # Note that +SYS_exit_group+ is allowed by default, and it must be allowed.
  #
  attr_reader :allowed_syscalls 

  #
  # Set of syscalls that the child process can make, but which have no effect.
  # More precisely, they behave like <tt>return 0;</tt>.
  #
  attr_reader :ignored_syscalls 

  #
  # Add the given syscalls to {#allowed_syscalls}.
  #
  def allow_syscalls *syscall_numbers
    @allowed_syscalls.merge(syscall_numbers)
  end

  #
  # Add the given syscalls to {#ignored_syscalls}.
  #
  def ignore_syscalls *syscall_numbers
    @ignored_syscalls.merge(syscall_numbers)
  end

  #
  # 
  #
  def syscall_ignored? syscall_number
    @ignored_syscalls.member?(syscall_number)
  end

  def syscall_allowed? syscall_number
    @allowed_syscalls.member?(syscall_number)
  end

  #
  # Run a command using <tt>Kernel.exec</tt> with the configured limits.
  #
  #def exec_with_limits *args
  #  with_limits { Kernel.exec(*args) }
  #end

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
      # call into native code to start tracing
      child_trace

      # run the caller's block
      yield
    }

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

    begin
      child_pid = fork {
        # close the parent end of the pipes from the child
        [out_r, err_r].each(&:close)

        begin
          # redirect stdout and stderr before tracing
          $stdout.reopen(out_w)
          $stderr.reopen(err_w)

          # call into native code to start tracing
          child_trace

          # run the caller's block
          yield
        ensure
          [out_w, err_w].each(&:close)
        end
      }

      # close the child end of the pipes from the parent
      [out_w, err_w].each(&:close)

      # call into native tracing code for the parent
      result = parent_trace(child_pid)

      [result, out_r.read, err_r.read]
    ensure
      [out_r, err_r].each(&:close)
    end
  end

  def spawn *args
    supervise {
      spawn_pid = Process.spawn(*args)
      Process.wait(spawn_pid)
      exit! $?.exitstatus
    }
  end

  private

  #
  # Close all file descriptors between +lo_fd+ and +hi_fd+ inclusive.
  #
  # @param [Integer] lo_fd lowest fd to close
  # @param [Integer] hi_fd highest fd to close
  # @return [nil]
  #
  def child_close_fds lo_fd, hi_fd=true
    # use a conservative default value
    if hi_fd == true
      hi_fd, hi_fd_hard = Process.getrlimit(:NOFILE)
      hi_fd -= 1 # the constant is one greater than the largest allowed value
    end

    (lo_fd..hi_fd).each do |fd|
      close(fd)
    end

    nil
  end
end

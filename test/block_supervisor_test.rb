require 'block_supervisor'
require 'test/unit'

#puts Dir.entries('/proc/self/fd')

class TestBlockSupervisor < Test::Unit::TestCase
  include Syscalls

  def test_getpid_allowed
    #
    # the child makes one syscall, SYS_getpid, and it's allowed, so everything
    # should go OK
    #
    s = BlockSupervisor.new
    s.allow_syscalls SYS_getpid
    result = s.supervise {
      Syscalls.syscall(SYS_getpid)
      exit! 0
    }
    assert_equal BlockSupervisor::ChildExited.new(0), result
  end

  def test_getpid_ignored
    #
    # when a syscall is ignored, its return value is forced to be zero;
    # to test this, we capture the output from the child process
    #
    s = BlockSupervisor.new
    s.allow_syscalls SYS_write
    s.ignore_syscalls SYS_getpid
    s.inherit_fds 0, 1, 2
    result, out, err = s.capture {
      print "pid=#{Syscalls.syscall(SYS_getpid)}"
      exit! 0
    }
    assert_equal BlockSupervisor::ChildExited.new(0), result
    assert_equal "pid=0", out
    assert_equal "", err
  end

  def test_getpid_disallowed
    #
    # the child tries to call SYS_getpid, but it's disallowed; the child should
    # be terminated
    #
    s = BlockSupervisor.new
    result = s.supervise {
      Syscalls.syscall(SYS_getpid)
      exit! 0
    }
    assert_equal BlockSupervisor::ChildSyscallDisallowed.new(SYS_getpid), result
  end

  def test_fds_are_closed
    #
    # open a file on the parent; the child should not be able to find it by fd
    #
    s = BlockSupervisor.new

    # check that we can change the set; we won't need STDIN, so we can close it
    s.inherited_fds.delete STDIN.fileno
    assert_equal Set[STDOUT.fileno, STDERR.fileno], s.inherited_fds

    # for_fd needs some syscalls 
    s.allow_syscalls SYS_fcntl64, SYS_rt_sigprocmask, SYS_ioctl, SYS_write

    File.open(__FILE__, 'r') do |f|
      result, out, err = s.capture {
        begin
          File.for_fd(f.fileno, 'r') # should not work
        rescue Errno::EBADF
          print "EBADF"
        end
        exit! 0
      }
      assert_equal BlockSupervisor::ChildExited.new(0), result
      assert_equal "EBADF", out
      assert_equal "", err
    end

    # check that we haven't leaked FDs from capture
    assert_equal Set[STDOUT.fileno, STDERR.fileno], s.inherited_fds
  end

#  def test_spawn
#    s = BlockSupervisor.new
#    s.allow_syscalls SYS_pipe, SYS_fcntl64, SYS_rt_sigprocmask, SYS_futex,
#      SYS_clone, SYS_close, SYS_read, SYS_waitpid
#    result = s.spawn('ls')
#    p result
#    p Syscalls::SYS_NAME[result.syscall_number] rescue nil
#  end
end


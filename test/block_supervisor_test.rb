require 'block_supervisor'
require 'test/unit'

class TestBlockSupervisor < Test::Unit::TestCase
  include Syscalls
  def test_getpid_allowed
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
    result, out, err = s.capture {
      print "pid=#{Syscalls.syscall(SYS_getpid)}"
      exit! 0
    }
    assert_equal BlockSupervisor::ChildExited.new(0), result
    assert_equal "pid=0", out
    assert_equal "", err
  end

  def test_getpid_disallowed
    s = BlockSupervisor.new
    result = s.supervise {
      Syscalls.syscall(SYS_getpid)
      exit! 0
    }
    assert_equal BlockSupervisor::ChildSyscallDisallowed.new(SYS_getpid),
      result
  end

  def test_spawn
    s = BlockSupervisor.new
    s.allow_syscalls SYS_pipe, SYS_fcntl64, SYS_rt_sigprocmask, SYS_futex,
      SYS_clone, SYS_close, SYS_read, SYS_waitpid
    result = s.spawn('ls')
    p result
    p Syscalls::SYS_NAME[result.syscall_number] rescue nil
  end
end


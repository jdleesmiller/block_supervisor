require 'block_supervisor'
require 'test/unit'
require 'tempfile'

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
    assert_equal "<BlockSupervisor::ChildSyscallDisallowed: 20 (SYS_getpid)>",
      result.inspect
  end

  def test_fds_are_closed
    #
    # open a file on the parent; the child should not be able to find it by fd
    #
    s = BlockSupervisor.new
    s.restrict_syscalls = false

    # check that we can change the set; we won't need STDIN, so we can close it
    s.inherited_fds.delete STDIN.fileno
    assert_equal Set[STDOUT.fileno, STDERR.fileno], s.inherited_fds

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
  end

  def test_rlimit_address_space
    #
    # try to allocate an array that exceeds the AS (address space) rlimit
    #
    big = 50_000_000 # allocate this much

    s = BlockSupervisor.new
    s.restrict_syscalls = false
    s.setrlimit :AS, big
    result, out, err = s.capture {
      begin 
        too_big = [0] * big
      rescue NoMemoryError
        print $!.class
      end
      exit! 0
    }
    assert_equal BlockSupervisor::ChildExited.new(0), result
    assert_equal "NoMemoryError", out
    assert_equal "", err
  end

  def test_timeout
    s = BlockSupervisor.new
    s.timeout = 1
    s.restrict_syscalls = false
    result = s.supervise {
      sleep 5
      exit! 0
    }
    assert_equal BlockSupervisor::ChildSignaled.new(Signal.list['ALRM']), result
    assert result.timeout?
  end

  def test_silence_streams
    s = BlockSupervisor.new
    s.restrict_syscalls = false
    s.child_stdout = nil
    s.child_stderr = nil
    result = s.supervise {
      $stdout.puts "this should not show up in the test output"
      $stderr.puts "this should not show up in the test output"
      exit! 0
    }
    assert_equal BlockSupervisor::ChildExited.new(0), result
  end

  def test_redirect_streams
    s = BlockSupervisor.new
    s.restrict_syscalls = false

    begin
      o = Tempfile.new('out')
      e = Tempfile.new('err')
      s.child_stdout = o
      s.child_stderr = e
      s.inherit_fds o.fileno, e.fileno
      result = s.supervise {
        $stdout.puts "OUT"
        $stderr.puts "ERR"
        $stdout.flush
        $stderr.flush
        exit! 0
      }
      assert_equal BlockSupervisor::ChildExited.new(0), result
      assert_equal "OUT", File.read(o.path).strip
      assert_equal "ERR", File.read(e.path).strip
    ensure
      o.close
      e.close
    end
  end
end

#    p Syscalls::SYS_NAME[result.syscall_number] rescue nil


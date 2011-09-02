#include <ruby.h>

#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

// TODO use PIDT2NUM

/**
 * Define SYS_SUP_DEBUG_TRACING to enable print statements for debugging.
 */
#define SYS_SUP_DEBUG_TRACING

#ifdef SYS_SUP_DEBUG_TRACING
#define SYS_SUP_DEBUG(msg) printf(msg)
#define SYS_SUP_DEBUG1(msg, x1) printf(msg, x1)
#define SYS_SUP_DEBUG2(msg, x1, x2) printf(msg, x1, x2)
#else
#define SYS_SUP_DEBUG(msg) /* do nothing */
#define SYS_SUP_DEBUG1(msg, x1) /* do nothing */
#define SYS_SUP_DEBUG2(msg, x1, x2) /* do nothing */
#endif

/**
 * Offsets, in bytes, into the user data segment of the system call number and
 * the system call return value. On x86, the ORIG_EAX and EAX offsets come from
 * sys/reg.h, where they are specified in 4-byte words. On x86_64 systems, the
 * corresponding values are ORIG_RAX and RAX.
 */
#ifdef __x86_64__
#define SYSCALL_OFF (ORIG_RAX * 8)
#define SYSCALL_RET (RAX * 8)
#else
#define SYSCALL_OFF (ORIG_EAX * 4)
#define SYSCALL_RET (EAX * 4)
#endif

static int block_sup_trap_syscall_enter(VALUE self, pid_t child_pid,
    long syscall)
{
  SYS_SUP_DEBUG1("entering call: %3d", syscall);

  if (rb_funcall(self, rb_intern("syscall_ignored?"), 1,
        LONG2FIX(syscall)) == Qtrue) {
    SYS_SUP_DEBUG("... ignored\n");

    /* replace the syscall with something harmless; we will replace its return
     * value with zero when the system call exits (see below) */
    if (ptrace(PTRACE_POKEUSER, child_pid, SYSCALL_OFF, SYS_getpid) == -1)
      rb_sys_fail("PTRACE_POKEUSER failed on ignored call");

    return -1; /* continue */
  } else if (rb_funcall(self, rb_intern("syscall_allowed?"), 1,
        LONG2FIX(syscall)) == Qtrue) {
    SYS_SUP_DEBUG("... allowed\n");

    return -1; /* continue */
  } else {
    SYS_SUP_DEBUG("... not allowed\n");

    /* replace the signal with exit_group; geordi does this in addition to
     * calling PTRACE_KILL, because ptrace allows the current (disallowed!)
     * syscall to finish, even after PTRACE_KILL is called */
    if (ptrace(PTRACE_POKEUSER, child_pid, SYSCALL_OFF, SYS_exit_group) == -1)
      rb_sys_fail("PTRACE_POKEUSER failed on disallowed call");

    return 0; /* kill child process */
  }
}

/**
 *
 */
int block_sup_trap_syscall_exit(VALUE self, pid_t child_pid, long syscall)
{
  SYS_SUP_DEBUG1("exiting call: %3d", syscall);

  if (rb_funcall(self, rb_intern("syscall_ignored?"), 1,
        LONG2FIX(syscall)) == Qtrue) {
    SYS_SUP_DEBUG("... ignored\n");

    /* replace the ignored system call's return value with 0 */
    if (ptrace(PTRACE_POKEUSER, child_pid, SYSCALL_RET, 0) == -1)
      rb_sys_fail("PTRACE_POKEUSER failed on disallowed syscall exit");
  } else {
    SYS_SUP_DEBUG("... no action\n");
  }

  return -1;
}

/**
 * Called from the child process to start tracing.
 */
static VALUE block_sup_child_trace(VALUE self) {
  /* child process here */
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);

  /* send stop signal to parent to initialize (see parent_trace) */ 
  raise(SIGSTOP);

  return Qnil;
}

/**
 * The tracing code in the parent process.
 *
 * This function initializes ptrace (sets options), and then it selects the
 * wait() events that correspond to trapped system calls; it passes these to
 * block_sup_trap_syscall_enter or block_sup_trap_syscall_exit.
 */
static VALUE block_sup_parent_trace(VALUE self, VALUE child_pid_val)
{
  pid_t child_pid = FIX2INT(child_pid_val);
  long syscall;
  int status, in_syscall;
  VALUE klass;

  klass = rb_funcall(self, rb_intern("class"), 0);

  /* the child sends SIGSTOP before doing anything else, which gives the parent 
   * a chance to initialize tracing */
  if (wait(&status) == -1)
    rb_sys_fail("wait for STOP failed");
  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
    rb_raise(rb_eRuntimeError, "first signal not SIGSTOP but %d", status);
  SYS_SUP_DEBUG1("got sigstop; child_pid=%d\n", child_pid);

  /* we assume that we're not in a syscall at the start */
  in_syscall = 0;
  syscall = 0;

  /* set the TRACESYSGOOD option; it lets us tell the difference between normal
   * traps (which we ignore) and traps caused by a syscall (which we watch) */
  if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_TRACESYSGOOD) == -1)
    rb_sys_fail("failed to set TRACESYSGOOD");

  /* done initializing; run child to next syscall (or to exit) */
  if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) == -1)
    rb_sys_fail("failed to resume after stop");

  /* now we are finally ready to start tracing */
  for (;;) {
    if (wait(&status) == -1)
      rb_sys_fail("wait failed");

    if (WIFEXITED(status)) {
      /* child process exited normally */
      return rb_funcall(rb_const_get(klass, rb_intern("ChildExited")),
          rb_intern("new"), 1, LONG2FIX(WEXITSTATUS(status)));
    }

    if (WIFSIGNALED(status)) {
      /* child process terminated by signal */
      return rb_funcall(rb_const_get(klass, rb_intern("ChildSignaled")),
          rb_intern("new"), 1, LONG2FIX(WTERMSIG(status)));
    }

    if (WIFSTOPPED(status)) {
      if (WSTOPSIG(status) == SIGTRAP) {
        /* because we set PTRACE_O_TRACESYSGOOD, this means that we have a trap
         * that is not a system call trap, so we should ignore it */
        if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) == -1)
          rb_sys_fail("ptrace failed (after sigtrap)");
      } else if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
        /* this is the event that we're interested in */
        if (!in_syscall) {
          /* find out which syscall we will be entering */
          in_syscall = -1;
          syscall = ptrace(PTRACE_PEEKUSER, child_pid, SYSCALL_OFF, NULL);
          if (syscall == -1 && errno != 0)
            rb_sys_fail("PTRACE_PEEKUSER failed on syscall entry");

          /* apply the syscall filter */
          if (!block_sup_trap_syscall_enter(self, child_pid, syscall))
            break; /* stop tracing and kill the child process */
        } else {
          /* we are now exiting the syscall that we entered above */
          if (!block_sup_trap_syscall_exit(self, child_pid, syscall))
            break; /* stop tracing and kill the child process */

          in_syscall = 0;
          syscall = 0; /* NB: don't clear syscall if killing child process */
        }

        /* we're still here; continue to next syscall trap */
        if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) == -1)
          rb_sys_fail("PTRACE_SYSCALL failed");
      } else {
        /* child was stopped by some other signal; send a kill (this is what
         * geordi does) */
        SYS_SUP_DEBUG("non-trap stop\n");
        break;
      }
    }
  }

  /* if we broke out of the loop above, we want to kill the child process;
   * we also want to make sure that we wait for it to die before returning */
  for (;;) {
    if (ptrace(PTRACE_KILL, child_pid, NULL, NULL) == -1)
      rb_sys_fail("PTRACE_KILL failed)");

    if (wait(&status) == -1) {
      /* if the child process has already been waited (ECHILD), that's fine */
      if (errno == ECHILD)
        break;

      /* otherwise, this was unexpected */
      rb_sys_fail("wait failed when waiting for child process to die");
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      break;
    }
  }

  return rb_funcall(rb_const_get(klass, rb_intern("ChildSyscallDisallowed")),
          rb_intern("new"), 1, LONG2FIX(syscall));
}

/**
 * Close all file descriptors from +lo_fd_v+ to +hi_fd_v+ inclusive.
 *
 * @param [Fixnum] hi_fd highest fd to close
 *
 * @return [Fixnum] the highest file descriptor that was closed, or -1 if no
 * file descriptors were closed
 */
static VALUE block_sup_child_close_fds(VALUE self, VALUE hi_fd)
{
  int fd, ret;
  int hi_fd_int = FIX2INT(hi_fd);
  int max_closed = -1;
  ID fd_inherited = rb_intern("fd_inherited?");

  for (fd = 0; fd <= hi_fd_int; ++fd) {
    if (rb_funcall(self, fd_inherited, 1, INT2FIX(fd)) != Qtrue) {
      ret = close(fd);
      if (ret != -1) {
        max_closed = fd;
      }
    }
  }

  return INT2FIX(max_closed);
}

void
Init_block_supervisor(void)
{
    VALUE klass = rb_define_class("BlockSupervisor", rb_cObject);
    rb_define_private_method(klass, "child_trace",
        block_sup_child_trace, 0);
    rb_define_private_method(klass, "parent_trace",
        block_sup_parent_trace, 1);
    rb_define_private_method(klass, "child_close_fds",
        block_sup_child_close_fds, 1);
}


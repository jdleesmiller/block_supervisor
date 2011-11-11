require 'mkmf'

# this was added in 1.9.3; it affects how we close file descriptors
have_func('rb_reserved_fd_p')

create_makefile('block_supervisor/block_supervisor')

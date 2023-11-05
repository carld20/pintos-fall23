#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);
int syscall_execute(const char *file_name);
void* verify_addr(const void *vaddr);
struct proc_file* search_files(struct list* files, int fd);
void close_file(struct list *files, int fd);
extern bool running;

struct proc_file {
  struct file* ptr;
  int fd;
  struct list_elem elem;
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int *p = f->esp;
  verify_addr(p);
  int system_call = *p;

  switch(system_call) {
    case SYS_HALT:
      shutdown_power_off();
      break;

    case SYS_EXIT:
      verify_addr(p+1);
      syscall_exit(*(p+1));
      break;

    case SYS_EXEC:
      verify_addr(p+1);
      verify_addr((void *)*(p+1));
      f->eax = syscall_execute((char *)*(p+1));
      break;

    case SYS_WAIT:
      verify_addr(p+1);
      f->eax = process_wait(*(p+1));
      break;

    case SYS_CREATE:
      verify_addr(p+5);
      verify_addr((void *)*(p+4));
      acquire_filesys_lock();
      f->eax = filesys_create((char *)*(p+4), *(p+5));
      release_filesys_lock();
      break;

    case SYS_REMOVE:
      verify_addr(p+1);
      verify_addr((void *)*(p+1));
      acquire_filesys_lock();
      f->eax = filesys_remove((char *)*(p+1));
      release_filesys_lock();
      break;

    case SYS_OPEN:
      verify_addr(p+1);
      verify_addr((void *)*(p+1));
      acquire_filesys_lock();
      struct file* file_ptr = filesys_open((char *)*(p+1));
      release_filesys_lock();
      if(file_ptr == NULL) {
        f->eax = -1;
      } else {
        struct proc_file *pfile = malloc(sizeof(*pfile));
        pfile->ptr = file_ptr;
        pfile->fd = thread_current()->fd_count;
        thread_current()->fd_count++;
        list_push_back(&thread_current()->files, &pfile->elem);
        f->eax = pfile->fd;
      }
      break;

    case SYS_FILESIZE:
      verify_addr(p+1);
      acquire_filesys_lock();
      f->eax = file_length(search_files(&thread_current()->files, *(p+1))->ptr);
      release_filesys_lock();
      break;

    case SYS_READ:
      verify_addr(p+7);
      verify_addr((void *)*(p+6));
      if(*(p+5) == STDIN_FILENO) {
        uint8_t *buffer = (uint8_t *)*(p+6);
        for(int i = 0; i < *(p+7); i++) {
          buffer[i] = input_getc();
        }
        f->eax = *(p+7);
      } else {
        struct proc_file* fptr = search_files(&thread_current()->files, *(p+5));
        if(fptr == NULL) {
          f->eax = -1;
        } else {
          acquire_filesys_lock();
          f->eax = file_read(fptr->ptr, (void *)*(p+6), *(p+7));
          release_filesys_lock();
        }
      }
      break;

    case SYS_WRITE:
      verify_addr(p+7);
      verify_addr((void *)*(p+6));
      if(*(p+5) == STDOUT_FILENO) {
        putbuf((char *)*(p+6), *(p+7));
        f->eax = *(p+7);
      } else {
        struct proc_file* fptr = search_files(&thread_current()->files, *(p+5));
        if(fptr == NULL) {
          f->eax = -1;
        } else {
          acquire_filesys_lock();
          f->eax = file_write(fptr->ptr, (void *)*(p+6), *(p+7));
          release_filesys_lock();
        }
      }
      break;

    case SYS_SEEK:
      verify_addr(p+5);
      acquire_filesys_lock();
      file_seek(search_files(&thread_current()->files, *(p+4))->ptr, *(p+5));
      release_filesys_lock();
      break;

    case SYS_TELL:
      verify_addr(p+1);
      acquire_filesys_lock();
      f->eax = file_tell(search_files(&thread_current()->files, *(p+1))->ptr);
      release_filesys_lock();
      break;

    case SYS_CLOSE:
      verify_addr(p+1);
      acquire_filesys_lock();
      close_file(&thread_current()->files, *(p+1));
      release_filesys_lock();
      break;
    
    default:
      printf("Unkown syscall %d\n", *p);
  }
}

int syscall_execute(const char *file_name) {
  char *saveptr;
  char *fn_copy = malloc(sizeof(file_name) + 1);
  strlcpy(fn_copy, file_name, strlen(file_name) + 1);
  fn_copy = strtok_r(fn_copy, " ", &saveptr);

  acquire_filesys_lock();
  struct file *f = filesys_open(fn_copy);

  if(f == NULL) {
    release_filesys_lock();
    return -1;
  } else {
    file_close(f);
    release_filesys_lock();
    return process_execute(file_name);
  }
}

void syscall_exit(int status) {
  struct list_elem *cur;
  for(cur = list_begin(&thread_current()->parent->child_proc); cur != list_end(&thread_current()->parent->child_proc); cur = list_next(cur)) {
    struct child *f = list_entry(cur, struct child, elem);
    if(f->tid == thread_current()->tid) {
      f->used = true;
      f->exit_error = status;
    }
  }

  thread_current()->exit_error = status;
  lock_acquire(&thread_current()->parent->child_lock);

  if(thread_current()->parent->waitingon == thread_current()->tid) {
    cond_signal(&thread_current()->parent->child_cond, &thread_current()->parent->child_lock);
    lock_release(&thread_current()->parent->child_lock);
    thread_exit();
  }
}

void* verify_addr(const void *vaddr) {
  if(!is_user_vaddr(vaddr)) {
    syscall_exit(-1);
    return 0;
  }
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if(!ptr) {
    syscall_exit(-1);
    return 0;
  }
  return ptr;
}

struct proc_file* search_files(struct list *files, int fd) {
  struct list_elem *cur;
  for(cur = list_begin(files); cur != list_end(files); cur = list_next(cur)) {
    struct proc_file *f = list_entry(cur, struct proc_file, elem);
    if(f->fd == fd) return f;
  }
  return NULL;
}

void close_file(struct list *files, int fd) {
  struct list_elem *cur;
  for(cur = list_begin(files); cur != list_end(files); cur = list_next(cur)) {
    struct proc_file *f = list_entry(cur, struct proc_file, elem);
    if(f->fd == fd) {
      file_close(f->ptr);
      list_remove(cur);
    }
  }
}

void close_all_files(struct list *files) {
  struct list_elem *cur;
  for(cur = list_begin(files); cur != list_end(files); cur = list_next(cur)) {
    struct proc_file *f = list_entry(cur, struct proc_file, elem);
    file_close(f->ptr);
    list_remove(cur);
  }
}



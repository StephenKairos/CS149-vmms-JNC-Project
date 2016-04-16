// This is a simple test program

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>

#include "vmms.h"

struct student
{
  int	ID;
  char	name[20];
  struct student *left;
  struct student *right;
};

int main()
{
  int rc = 0;
  char *student_ptr;
  char *list;


  list = (char*) vmms_malloc(50, &rc);

  if (list == NULL)
    return 1;

  strcpy (list, "dummy1");
  strcpy (list+10, "911");

  printf("list address = %8x; Name = %s; ID = %i\n", list, list, (char*)list+10);

  system("pause");
  
  vmms_write_bin();
  //rc = vmms_free((char*)list);

  return rc;
}

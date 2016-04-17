/*
vmms.cpp - This file contains the code for each of the memory functions as well as initialization of the "shared" memory.
*/
#include "vmms_error.h"

//My Imports (- Stephen Reyes)
#include <string.h>
#include <time.h>
#include <iostream>
#include <windows.h>
#include "psapi.h"

#define MAX_PHY_SIZE 8196    // 8K Bytes     ** Hardcode for testing !!
#define MAX_TABLE_SIZE 1024  // 1K entries
#define DEFAULT_BOUNDARY 8    // minimum 8 byte allocation block
#define FREE_FILLER 0xFF // filler for free blocks

// ************************************************************************
// Global Shared variables (shared by multiple instances of the DLL)
// ************************************************************************

/* Global shared memory section */
#pragma data_seg (".SHARED")  // Simulated Physical Mem // Hardcoded for now !!
int byte_boundary = DEFAULT_BOUNDARY;
int mem_size = MAX_PHY_SIZE;            // size of simulated phy mem (in bytes)
char mem_start [MAX_PHY_SIZE] = {0};  	// simulated Phy Memory

//My Stuff
bool booted = false;

// struct mEntry {
//   int PID;
//   char * addr;
//   int rSize;
//   int aSize;
// } mTable[MAX_TABLE_SIZE];
//
// struct fEntry {
//   char * addr;
//   int size;
// } fList[MAX_TABLE_SIZE];

bool testFlag = false;
bool test = false;
#pragma data_seg ()
#pragma comment(linker, "/SECTION:.SHARED,RWS")

#pragma bss_seg(".STRUCT_SHARED")
struct mEntry {
  int PID;
  char * addr;
  int rSize;
  int aSize;
} mTable[MAX_TABLE_SIZE];

struct fEntry {
  char * addr;
  int size;
} fList[MAX_TABLE_SIZE];
#pragma bss_seg ()
#pragma comment(linker, "/SECTION:.STRUCT_SHARED,RWS")

// Map table Structures/Entries

//Need to implement a constructor
// bool booted = false;
//
// struct mEntry {
//   int PID;
//   char * addr;
//   int rSize;
//   int aSize;
//   mEntry() {
//     PID = NULL;
//     addr = mem_start;
//     rSize = -1;
//     aSize = -1;
//   }
// } mTable[MAX_TABLE_SIZE];
//
// struct fEntry {
//   char * addr;
//   int size;
//   fEntry() {
//     addr = mem_start;
//     size = -1;
//   }
// } fList[MAX_TABLE_SIZE];

time_t now;
struct tm *tm;

//

/* Here are the 5 exported functions for the application programs to use */
__declspec(dllexport) char* vmms_malloc (  int size, int* error_code );
__declspec(dllexport) int vmms_memset ( char* dest_ptr, char c, int size );
__declspec(dllexport) int vmms_memcpy ( char* dest_ptr, char* src_ptr, int size );
__declspec(dllexport) int vmms_print ( char* src_ptr, int size );
__declspec(dllexport) int vmms_free ( char* mem_ptr );

/* Here are several exported functions specifically for mmc.cpp */
__declspec(dllexport) int mmc_initialize (  int boundary_size );
__declspec(dllexport) int mmc_display_memtable ( char* filename );
__declspec(dllexport) int mmc_display_memory ( char* filename );

/*My Exported Functions*/
__declspec(dllexport) int vmms_write_bin();

//Helper Functions
_declspec(dllexport) bool vmms_boot() {
  booted = true;

  for (int i = 0; i < MAX_TABLE_SIZE; i++) {
    mEntry m;
    m.PID = NULL; m.addr = mem_start; m.rSize = -1; m.aSize = -1;
    mTable[i] = m;
  }

  for (int i = 0; i < MAX_TABLE_SIZE; i++) {
    fEntry f;
    f.addr = mem_start; f.size = -1;
    fList[i] = f;
  }

  fList[0].size = MAX_PHY_SIZE;

  printf("Start of mem: %i\nEnd of mem: %i\n", &mem_start, &mem_start[MAX_PHY_SIZE]);
  return booted;
}

__declspec(dllexport) int vmms_write_bin() {
  FILE *memFile;
  memFile = fopen("vmms_mem.bin", "w+");
  //fwrite(mem_start, sizeof(mem_start[0]), sizeof(mem_start)/sizeof(mem_start[0]), memFile);

  for(size_t i = 0; i < sizeof(mem_start) /*&& mem_start[i] != NULL*/; i++) {
    fprintf(memFile, "%c", mem_start[i]);
  }
  fclose(memFile);

  return 0;
}

//Main Functions

__declspec(dllexport) int mmc_initialize (  int boundary_size ) {
  int rc = VMMS_SUCCESS;
  byte_boundary = boundary_size;
  testFlag = true;
  printf("%i\n", &testFlag);

  if( testFlag) {
    printf("SUCCESS\n");
  } else {
    printf("FAIL\n");
  }

  return rc;
}

__declspec(dllexport) int mmc_display_memtable ( char* filename ) {
  int rc = VMMS_SUCCESS;

  if(!booted) { vmms_boot(); }

  FILE *fp;
  if(filename != NULL) {
    fp = fopen(filename, "w+");
  }

  /* Put your source code here */
  int mPos = 0;
  printf("%i\n", mTable[mPos].rSize);
  while(mTable[mPos].rSize != -1) {
    mEntry m = mTable[mPos];
    printf("%i - PID: %i, Address: %i, Requested Size: %i, Actual Size: %i\n", mPos + 1, m.PID, m.addr, m.rSize, m.aSize);
    if(filename != NULL) {

    }
    mPos++;
  }
  fclose(fp);

  return rc;
}

__declspec(dllexport) int mmc_display_memory ( char* filename ) {
  int rc = VMMS_SUCCESS;

  if(!booted) { vmms_boot(); }
  /* Put your source code here */

  return rc;
}

__declspec(dllexport) char* vmms_malloc (  int size, int* error_code ) {
  /* Put your source code here */
  *error_code = VMMS_SUCCESS;

  printf("%i\n", &testFlag);
  if(testFlag) {
    printf("SUCCESS\n");
  } else {
    printf("FAIL\n");
  }

  //Always boot
  if(!booted) { vmms_boot(); }

  printf("%i\n", fList[0].size);

  //Set size in accordance with the byte_boundary
  int reqSize = size;
  int actualSize = reqSize + byte_boundary - 1 - ((reqSize - 1) % byte_boundary);
  printf("rSize: %i\naSize: %i\n", reqSize, actualSize);

  // Doing memory allocation here
  // Allocate to exact fit, or to the largest block, for actual size
  // Checking our free list for available spots
  printf("Checking free list...\n");
  int fPos = 0;
  int currentPos = fPos;
  fEntry currentSlot = fList[fPos];
  while(fList[fPos + 1].size != -1) {
    if(fList[fPos].size == actualSize) {
      currentSlot = fList[fPos];
      currentPos = fPos;
      break;
    } else if(fList[fPos].size > currentSlot.size) {
      currentSlot = fList[fPos];
      printf("Current Slot Size: %i", currentSlot.size);
      if(fList[fPos + 1].size == -1) {
        currentPos = fPos;
        break;
      }
    }
    fPos++;
  }

  printf("FPOS: %i\n", fList[0].addr);

  //Setup position in mem table for insertion
  printf("Finding memory table slot...\n");
  int mPos = 0;
  while(mTable[mPos].rSize >= 0) {
    mPos++;
  }

  //Check if size of new item is bigger than the current noted free space
  printf("Checking size...\nCurrent Size: %i\nmPos: %i\n", currentSlot.size, mPos);
  if(actualSize > currentSlot.size || mPos > MAX_TABLE_SIZE)  {
    *error_code = OUT_OF_MEM;
    printf("ERROR: Too small. Terminated.");
    return NULL;
  }

  // A slot exists! Create entry into the memory table
  printf("Success! Entry created.\n");
  mEntry insert;
  insert.PID = GetCurrentProcessId();
  insert.addr = currentSlot.addr;
  insert.rSize = reqSize;
  insert.aSize = actualSize;

  mTable[mPos] = insert;

  //Set new free slot, delete old
  fList[0].size -= actualSize;
  printf("NEW SIZE: %i\n", fList[0].size);
  fList[0].addr += actualSize;

  //Insert file creation/append code here
  FILE *fp;
  fp = fopen("vmms_log.txt", "a");

  now = time(0);
  if ((tm = localtime (&now)) == NULL) {
    printf ("ERROR: TIMESTAMP ACCESS FAILED\n");
    *error_code = CALL_ERROR;
    return NULL;
  }

  fprintf (fp, "%04d%02d%02d%02d%02d%02d ",
  tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
  tm->tm_hour, tm->tm_min, tm->tm_sec);

  //Program Name
  char  nameBuffer[MAX_PATH];
  GetModuleBaseName(GetCurrentProcess(), NULL, nameBuffer, _MAX_FNAME);

  fprintf(fp, "%s ", nameBuffer);

  //Process ID
  fprintf(fp, "%i\n", GetCurrentProcessId());

  fprintf(fp, "    vmms_malloc %i %i %i %i\n", currentSlot.addr, 4096, size, *error_code);


  fclose(fp);



  return currentSlot.addr;             // for testing
}

__declspec(dllexport) int vmms_memset ( char* dest_ptr, char c, int size ) {
  int rc = VMMS_SUCCESS;

  /* Put your source code here */

  if(!booted) { vmms_boot(); }

  //Notes:
  // * Need to set a struct for table, includes, a PID, address of item, requested size ( like 5 bytes),
  //   and actual size (rounded to nearest divisible by the byte_boundary (for default, 8 bytes)
  // * UPDATED: Created struct for table and free blocks above, mEntry and fEntry, with mTable and fList

  //setting actual size (OUTDATED, commented out for now)
  // int reqSize = size;
  // int actualSize = reqSize + byte_boundary - 1 - ((reqSize - 1) % byte_boundary);

  //Also need to keep a struct for a Free_List, of free blocks, with the address of the free blocks and current size of each blocks
  //Initially it starts at mem_start
  //Hex of char c into the slot in dest_ptr, byte by byte

  //Check if writing to free space
  int fPos = 0;
  fEntry freeSpace = fList[fPos];
  while(freeSpace.size != -1) {
    //Adding data to unallocated space. Throw error.
    if(dest_ptr >= freeSpace.addr && dest_ptr <= freeSpace.addr + freeSpace.size) {
      return INVALID_DEST_ADDR;
    }
    fPos++;
    freeSpace = fList[fPos];
  }

  //Check position of memory if valid
  int mPos = 0;
  mEntry memSpace = mTable[mPos];
  while(memSpace.rSize != -1) {
    if(dest_ptr >= memSpace.addr && dest_ptr <= memSpace.addr + memSpace.aSize) {
      if(GetCurrentProcessId() != memSpace.PID) {
        return INVALID_DEST_ADDR; //Trying to write to someone else's allocated space
      } else if(memSpace.aSize - (dest_ptr - memSpace.addr) < size) {
        return MEM_TOO_SMALL; //Too small of a space to write/erase
      } else {
        break;
      }
    }
    mPos++;
    memSpace = mTable[mPos];
  }

  //Success! Available space to write to, so fill 'er up!
  for(int i = 0; i < size; i++) {
    *(memSpace.addr + i) = c;
  }

  //Insert file creation/append code here
  FILE *fp;
  fp = fopen("vmms_log.txt", "a");

  now = time(0);
  if ((tm = localtime (&now)) == NULL) {
    printf ("ERROR: TIMESTAMP ACCESS FAILED\n");
    return CALL_ERROR;
  }

  fprintf (fp, "%04d%02d%02d%02d%02d%02d ",
  tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
  tm->tm_hour, tm->tm_min, tm->tm_sec);

  //Program Name
  char  nameBuffer[MAX_PATH];
  GetModuleBaseName(GetCurrentProcess(), NULL, nameBuffer, _MAX_FNAME);

  fprintf(fp, "%s ", nameBuffer);

  //Process ID
  fprintf(fp, "%i\n", GetCurrentProcessId());

  fprintf(fp, "    vmms_memset %i %i %i %i %i\n", rc, 4096, dest_ptr, c, size);


  fclose(fp);



  return rc;
}


__declspec(dllexport) int vmms_memcpy ( char* dest_ptr, char* src_ptr, int size ) {
  int rc = VMMS_SUCCESS;

  /* Put your source code here */

  if(!booted) { vmms_boot(); }

  //Check if writing/reading to free (unallocated) space
  int fPos = 0;
  fEntry freeSpace = fList[fPos];
  while(freeSpace.size != -1) {
    if((dest_ptr >= freeSpace.addr && dest_ptr <= freeSpace.addr + freeSpace.size) || (src_ptr >= freeSpace.addr && src_ptr <= freeSpace.addr + freeSpace.size)) {
      //Adding/Getting data to/from unallocated space. Throw error.
      return INVALID_CPY_ADDR;
    }
    fPos++;
    freeSpace = fList[fPos];
  }

  //Check position of memory if valid
  int mPos = 0;
  mEntry memSpace = mTable[mPos];
  while(memSpace.rSize != -1) {
    if((dest_ptr >= memSpace.addr && dest_ptr <= memSpace.addr + memSpace.aSize) || (src_ptr >= memSpace.addr && src_ptr <= memSpace.addr + memSpace.aSize)) {
      if(GetCurrentProcessId() != memSpace.PID) {
        return INVALID_CPY_ADDR; //Trying to write to someone else's allocated space
      } else if((memSpace.aSize - (dest_ptr - memSpace.addr) < size) || (memSpace.aSize - (src_ptr - memSpace.addr))) {
        return MEM_TOO_SMALL; //Too small of a space to write/erase/copy
      }
    }
    mPos++;
    memSpace = mTable[mPos];
  }

  //Success! Available space to write to and the source is valid, so fill 'er up!
  for(int i = 0; i < size; i++) {
    *(dest_ptr + i) = *(src_ptr + i);
  }

  //Insert file creation/append code here
  FILE *fp;
  fp = fopen("vmms_log.txt", "a");

  now = time(0);
  if ((tm = localtime (&now)) == NULL) {
    printf ("ERROR: TIMESTAMP ACCESS FAILED\n");
    return CALL_ERROR;
  }

  fprintf (fp, "%04d%02d%02d%02d%02d%02d ",
  tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
  tm->tm_hour, tm->tm_min, tm->tm_sec);

  //Program Name
  char  nameBuffer[MAX_PATH];
  GetModuleBaseName(GetCurrentProcess(), NULL, nameBuffer, _MAX_FNAME);

  fprintf(fp, "%s ", nameBuffer);

  //Process ID
  fprintf(fp, "%i\n", GetCurrentProcessId());

  fprintf(fp, "    vmms_memcpy %i %i %i %i %i\n", rc, 4096, dest_ptr, src_ptr, size);


  fclose(fp);



  return rc;
}


__declspec(dllexport) int vmms_print ( char* src_ptr, int size ) {
  int rc = VMMS_SUCCESS;

  if(!booted) { vmms_boot(); }

  if((src_ptr >= &mem_start[0]) && (src_ptr <= &mem_start[MAX_PHY_SIZE])) {

    /* Put your source code here */
    //Check if reading free (unallocated) space
    int fPos = 0;
    fEntry freeSpace = fList[fPos];
    while(freeSpace.size != -1) {
      if(src_ptr >= freeSpace.addr && src_ptr <= freeSpace.addr + freeSpace.size) {
        //Getting data from unallocated space. Throw error.
        return INVALID_CPY_ADDR;
      }
      fPos++;
      freeSpace = fList[fPos];
    }

    //Check position of memory if valid
    int mPos = 0;
    mEntry memSpace = mTable[mPos];
    while(memSpace.rSize != -1) {
      if(src_ptr >= memSpace.addr && src_ptr <= memSpace.addr + memSpace.aSize) {
        if(GetCurrentProcessId() != memSpace.PID) {
          return INVALID_CPY_ADDR; //Trying to write to someone else's allocated space
        } //Too small of a space to write/erase/copy
      }
      mPos++;
      memSpace = mTable[mPos];
    }
  }
  //Success! Available space to write to and the source is valid, so fill 'er up!
  if(size != 0) {
    for(int i = 0; i < size; i++) {
      printf("%c", *(src_ptr + i));
    }
  } else {
    int i = 0;
    while(*(src_ptr + i) == NULL) { //If size == 0, keep printing until HEX 0, need to verify wheteher this is correct or not
      printf("%c", *(src_ptr + i));
      i++;
    }
  }
  //Insert file creation/append code here
  FILE *fp;
  fp = fopen("vmms_log.txt", "a");

  now = time(0);
  if ((tm = localtime (&now)) == NULL) {
    printf ("ERROR: TIMESTAMP ACCESS FAILED\n");
    return CALL_ERROR;
  }

  fprintf (fp, "%04d%02d%02d%02d%02d%02d ",
  tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
  tm->tm_hour, tm->tm_min, tm->tm_sec);

  //Program Name
  char  nameBuffer[MAX_PATH];
  GetModuleBaseName(GetCurrentProcess(), NULL, nameBuffer, _MAX_FNAME);

  fprintf(fp, "%s ", nameBuffer);

  //Process ID
  fprintf(fp, "%i\n", GetCurrentProcessId());

  fprintf(fp, "    vmms_print %i %i %i %i\n", rc, 4096, src_ptr, size);


  fclose(fp);



  return rc;
}

__declspec(dllexport) int vmms_free ( char* mem_ptr ) {
  int rc = VMMS_SUCCESS;

  /* Put your source code here */

  if(!booted) { vmms_boot(); }



  //Pointer address to free must match one of the pointers in the table, and match PID
  //Add new entry to Free_List with addr & size of memtable entry
  //Call memset before freeing, use 0xff for the values
  //memset(mem_ptr, 0xff, size);
  //Check position of memory if valid
  printf("Looking for valid memory address to free...\n");
  int mPos = 0;
  mEntry memSpace = mTable[mPos];
  while(memSpace.rSize != -1) {
    if(mem_ptr == memSpace.addr) {
      if(GetCurrentProcessId() != memSpace.PID) {
        printf("ERROR: NO AUTHORIZATION. Access terminated.\n");
        return INVALID_MEM_ADDR;
      }
      break;
    }
    mPos++;
    memSpace = mTable[mPos];
  }

  //The slot has not been allocated, and is already free
  if(memSpace.rSize < 0) {
    printf("ERROR: MEMORY ALREADY FREED.\n");
    return INVALID_MEM_ADDR;
  }

  //Success, slot can be freed.
  bool emptyBefore = false;
  bool emptyAfter = false;
  int before;
  int after;

  char * memPointer = memSpace.addr;
  int memSize = memSpace.aSize;
  memSpace.rSize = -2; //setting the point as free on the table

  printf("Setting memory as 0xFF for each character...\n");
  vmms_memset(memSpace.addr, FREE_FILLER, memSpace.aSize); //Setting memory

  printf("Looking through free spaces for adjacent merging...\n");
  //Cycle through fList
  int fPos = 0;
  fEntry freeSpace = fList[fPos];
  while(freeSpace.size != -1) {
    if(freeSpace.addr + freeSpace.size == memPointer) {
      emptyBefore = true;
      before = fPos;
    } else if(freeSpace.addr == memSpace.addr + memSpace.aSize) { //The slot directly after the current slot to be freed
      emptyAfter = true;
      after = fPos;
      break;
    }
    fPos++;
    freeSpace = fList[fPos];
  }

  //Checking cases requiring merging
  if(emptyBefore && emptyAfter) { //Empty space before and after
    fList[before].size += memSize + fList[after].size;
    fList[after].size = -2;
    printf("Merging spaces before and after...\n");
  } else if (emptyBefore) {
    fList[before].size += memSize;
    printf("Merging spaces with previous...\n");
  } else if (emptyAfter) {
    fList[after].addr = memPointer;
    fList[after].size += memSize;
    printf("Merging spaces with after...\n");
  } else {
    fList[fPos].addr = memPointer;
    fList[fPos].size = memSize;
    printf("Adding new fEntry...\n");
  }

  //Logging to file
  printf("Logging to file...\n");
  //Insert file creation/append code here
  FILE *fp;
  fp = fopen("vmms_log.txt", "a");

  now = time(0);
  if ((tm = localtime (&now)) == NULL) {
    printf ("ERROR: TIMESTAMP ACCESS FAILED\n");
    return CALL_ERROR;
  }

  fprintf (fp, "%04d%02d%02d%02d%02d%02d ",
  tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
  tm->tm_hour, tm->tm_min, tm->tm_sec);

  //Program Name
  char  nameBuffer[MAX_PATH];
  GetModuleBaseName(GetCurrentProcess(), NULL, nameBuffer, _MAX_FNAME);

  fprintf(fp, "%s ", nameBuffer);

  //Process ID
  fprintf(fp, "%i\n", GetCurrentProcessId());

  fprintf(fp, "    vmms_free %i %i %i\n", rc, 4096, mem_ptr);


  fclose(fp);
  printf("Success!\n");

  return rc;
}

/*
 * Example compiler
 * Copyright (C) 2015-2016 Scott Owens
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Modified in 03/2026 by Matas.
 *
 * Updated the compiler allocation helpers to call the internal GcMalloc
 * function, allowing allocated objects to be tracked for garbage collection.
 */

/* Allocation of multi-dimensional arrays of 64-bit ints. For an array of
 * length n, store the length of the array in element 0, and the array in 1 to
 * n inclusive. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <dlfcn.h>
#include <link.h>
#include <string.h>

#ifndef _ENABLE_GC
#define _ENABLE_GC 1
#endif

#ifndef _DEBUG_GC
#define _DEBUG_GC 0
#endif 

#if _DEBUG_GC
  #define GC_DEBUG(...) printf(__VA_ARGS__)
#else
  #define GC_DEBUG(...) ((void)0)
#endif

#define _In_
#define _In_opt_
#define _Out_
#define _Out_opt_
#define _Inout_opt_

#define OBJECT_INT_ARRAY 1
#define OBJECT_PTR_ARRAY 2

bool ElfInfoRetrieved = false;
Dl_info gDlInfo = { 0 };
Elf64_Ehdr* gElfHeader = (Elf64_Ehdr*)NULL;

/* 
* Simple linked list 
*/
typedef struct _ALLOCATED_OBJECT_LIST
{
  struct _ALLOCATED_OBJECT_LIST* NextObject;
  uint8_t Mark;
  uint8_t ObjectType;
  uint64_t Length;
} ALLOCATED_OBJECT_LIST, *PALLOCATED_OBJECT_LIST;

#define MAX_SEGMENTS 32

// 
// Used to store the range of each segment from the Elf executable, 
// for easy access to globals we need to scan 
//
typedef struct _RANGE_DESCRIPTOR
{
  uint64_t Low;
  uint64_t High;

} RANGE_DESCRIPTOR, *PRANGE_DESCRIPTOR;

typedef struct _SEGMENT_DESCRIPTOR
{
  RANGE_DESCRIPTOR SegmentRanges[MAX_SEGMENTS];
  uint64_t         Count;

} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

SEGMENT_DESCRIPTOR     gSegmentsDescriptor = { 0 };
PALLOCATED_OBJECT_LIST gAlloctedObjects = (PALLOCATED_OBJECT_LIST)NULL;

uint64_t ProgramStackBase = 0;
bool GcScan = true;

/* Since the first element of an array will have a different Type than the
 * rest, and the last dimension's array will have numbers rather than pointers.
 * (A "flexible array member", available since C99, would be another, nicer way
 * of doing this.) */
union elt {
  uint64_t num;
  union elt *ptr;
};

/* Our compiler will assume that the integers and pointers in the array are
 * both exactly 64 bits in size. So let's check that our C compiler shares
 * the same understanding of this data structure. */
_Static_assert (sizeof (uint64_t)  == sizeof (uintptr_t), "uint64_t is uintptr_t");
_Static_assert (sizeof (uint64_t)  == 8, "uint64_t is exactly 64 bits in size");
_Static_assert (sizeof (union elt) == 8, "union fits in 64 bits");

typedef union elt elt;

#define S sizeof(elt)

//
// This is called on _entry, installed by compiler to easily get 
// a base stack address. 
//
void 
GetStackBase(
  uint64_t StackPointer
)
{
  if( ProgramStackBase == 0 ) // to make sure it is only set once!
  {
      ProgramStackBase = StackPointer;
  }
}

//
// Get the current exectuble we are running in, assumes the machine
// is a 64-bit system
//
bool 
GetCurrentElfExecutable(
    _Out_opt_ Dl_info* DlInfo,
    _Out_opt_ Elf64_Ehdr** BaseHeader
)
{
  void* Dynamic = _DYNAMIC;
  Dl_info Info;
  if( !dladdr( Dynamic, &Info ) )
  {
    printf("Failed to get elf info\n");
    return false;
  }

  gDlInfo = Info;
  if( DlInfo )
  {
    *DlInfo = Info;
  }

  Elf64_Ehdr* ElfHeader = (Elf64_Ehdr*)Info.dli_fbase;
  gElfHeader = ElfHeader;
  if( BaseHeader )
  {
      *BaseHeader = ElfHeader;
  }

  ElfInfoRetrieved = true;
  return true;
}

bool
DumpElfSections(

)
{
  if( gElfHeader == NULL )
  {
    printf("Not retrieved elf head yet\n");
    return false;
  }

#define IsSegmentRwData(PrgHdr) \
  ((PrgHdr->p_type == PT_LOAD) && ((PrgHdr->p_flags & (PF_R|PF_W)) == (PF_R|PF_W)))

  // Program headers describe each segment loaded into memory similar to dos headers
  Elf64_Phdr* ProgramHeaders = (Elf64_Phdr*)(((uint8_t*)gElfHeader) + gElfHeader->e_phoff);
  gSegmentsDescriptor.Count   = 0;

  for( uint32_t Index = 0; (Index < gElfHeader->e_phnum) && (gSegmentsDescriptor.Count < MAX_SEGMENTS); ++Index )
  { 
    Elf64_Phdr* Segment = &ProgramHeaders[Index];
    if( !IsSegmentRwData( Segment ) ) // only want to check data segments as anaylsing .text is not it aswell as rwx permissions
    {
      continue;
    }

    PRANGE_DESCRIPTOR Range = &gSegmentsDescriptor.SegmentRanges[gSegmentsDescriptor.Count++];
    printf("ElfHeader %p, Segment vaddr 0x%llx\n",gElfHeader, Segment->p_vaddr, ProgramStackBase);
    Range->Low  = (uint64_t)(((uint64_t)gElfHeader) + Segment->p_vaddr); // vaddr is offset from ElfHeader...if its a dynamic image. lets hope its never not.
    Range->High = (uint64_t)(Range->Low + Segment->p_memsz);
  }

  return true;
}

//
// On a given address, iterate each allocated object against the address 
//
PALLOCATED_OBJECT_LIST
FindObject( 
  uint64_t Address
)
{
  for( PALLOCATED_OBJECT_LIST Object = gAlloctedObjects; Object; Object = Object->NextObject )
  {
    // check if the pointed to address is within the allocated data region
    uint64_t Low  = (uint64_t)(void*)(Object + 1);
    uint64_t High = Low + Object->Length;
    if( Address >= Low && Address < High )
    {
      return Object;
    }
  }
  return NULL;
}

void
GcMarkObject(
  PALLOCATED_OBJECT_LIST Object
)
{
  // check if object is already marked
  if( !Object || Object->Mark )
  {
    return;
  }

  // Mark this object
  Object->Mark = 1;

  // only recurse further if it is a multi-dimensional array!
  if( Object->ObjectType != OBJECT_PTR_ARRAY )
  {
    return;
  }

  //
  // Arrays are structured where index 0 is the lenght of the current array, 
  // and as we know this is a array of ptrs we find where each ptr points to !
  //
  elt* Array = (elt*)(Object+1);
  for( uint64_t Index = 0; Index < Array[0].num; ++Index )
  {
    // check if it is a valid pointer
    if( !(uint64_t)(Array[Index + 1].ptr) )
    {
      continue;
    }

    // recurse !
    PALLOCATED_OBJECT_LIST ObjectsChild = FindObject((uint64_t)Array[Index + 1].ptr);
    if( ObjectsChild )
    {
      GcMarkObject( ObjectsChild );
    }
  }
}

//
// This is the implementation of the 'mark' phase of the conservatice garbage collector, 
// where given an address in the range, checks if it points to an allocated object.
//
void
GcScanRange( 
  uint64_t Low, 
  uint64_t High
)
{
  if( gElfHeader == NULL )
  {
    return;
  }

  for( uint64_t* Index = (uint64_t*)Low; Index < (uint64_t*)High; ++Index )
  {
    if( !*Index )
    {
      continue;
    }

    PALLOCATED_OBJECT_LIST Object = FindObject(*Index);
    if( Object )
    {
      GC_DEBUG( "Found an object at %p\n", (void*)Object );
      GcMarkObject(Object);
    }
  }
}

//
// Goes through data segments retrieved from Elf program headers to find pointers 
// referncing our allocated objects
//
void 
GcMarkDataSegment( 
  void 
)
{
  if( gElfHeader == NULL )
  {
    return;
  }

  for( uint64_t Index = 0; Index < gSegmentsDescriptor.Count; ++Index )
  {
    GcScanRange( gSegmentsDescriptor.SegmentRanges[Index].Low, gSegmentsDescriptor.SegmentRanges[Index].High );
  }
}

//
// Goes through current rsp to entry rsp to look for pointers to our 
// allocated objects
//
void 
GcMarkStack(
  void
)
{
  uint64_t Low  = 0;
  __asm__ volatile("mov %%rsp, %0" : "=r"(Low));
  uint64_t High = ProgramStackBase;

  if( High > Low )
  {
    GcScanRange( Low, High );
  }
}

//
// Once objects are scanned and marked, iterate over every object
// and if it is not marked (not referenced by anything) then free it!
// 
void 
GcSweep(
  void 
)
{
  // points to first object
  for( PALLOCATED_OBJECT_LIST* Object = &gAlloctedObjects; *Object; )
  {
    // temporarily point to this object
    PALLOCATED_OBJECT_LIST Temp = *Object;

    if( !Temp->Mark )
    {
      //
      // Point iterative 'Object' to the next Object which in term removes Temp
      // from linked list. Then free it.
      //
      *Object = Temp->NextObject;
      //
      // causes alot of overhead, for large allocations has to go through and zero everything. uncessary. 
      // use more for debugging purposes 
      //
      // memset( (void*)Temp, 0x0, sizeof(*Temp) + (uint64_t)Temp->Length);
      free( Temp );
    }
    else
    {
      // 
      // Object is recheable by something so clear mark and 
      // get the next object.
      //
      Temp->Mark = 0;
      Object = &Temp->NextObject;
    }
  }
}

void 
GcMarkAndSweep(

)
{

  GC_DEBUG("-- Stack --\n");

  // just push all registers to stack for when I check stack! 
  // make sure to not break 16 byte alignment
__asm__ volatile(
    "push %%rax\n\t"
    "push %%rbx\n\t"
    "push %%rcx\n\t"
    "push %%rdx\n\t"
    "push %%rsi\n\t"
    "push %%rdi\n\t"
    "push %%r8\n\t"
    "push %%r9\n\t"
    "push %%r10\n\t"
    "push %%r11\n\t"
    "push %%r12\n\t"
    "push %%r13\n\t"
    "push %%r14\n\t"
    "push %%r15\n\t"
    :
    :
    : "memory"
 );

 GcMarkStack();

 __asm__ volatile(
    "pop %%r15\n\t"
    "pop %%r14\n\t"
    "pop %%r13\n\t"
    "pop %%r12\n\t"
    "pop %%r11\n\t"
    "pop %%r10\n\t"
    "pop %%r9\n\t"
    "pop %%r8\n\t"
    "pop %%rdi\n\t"
    "pop %%rsi\n\t"
    "pop %%rdx\n\t"
    "pop %%rcx\n\t"
    "pop %%rbx\n\t"
    "pop %%rax\n\t"
    :
    :
    : "memory"
  );


  GC_DEBUG("-- Data --\n");
  GcMarkDataSegment();
  GC_DEBUG("-- End --\n");
  GcSweep();
  return;
}

//
// the idea behind this is for each malloc call, add our own structure as a sort of 
// 'marker' to each allocated heap object. We then every set amount of time iterate heap and stack
// to look for allocted objects no longer referenced to free them by identifying them with our marker
//
#if _ENABLE_GC
void* 
GcMalloc( 
    uint64_t Sz,
    uint8_t Type
)
{
  if( !ElfInfoRetrieved )
  {
    Dl_info Info = { 0 };
    Elf64_Ehdr* ElfHeader = NULL;
    bool DidNotFail = GetCurrentElfExecutable( &Info, &ElfHeader );
    if( DidNotFail )
    {
      GC_DEBUG("Elf base -> 0x%llx\n", Info.dli_fbase);
      DumpElfSections();
    }

    GC_DEBUG( "Stack ptr 0x%llx\n", ProgramStackBase );
  }

  if( Sz == 0 )
  {
      return NULL;
  }

  if( GcScan )
  {
    GcMarkAndSweep();
  }

  PALLOCATED_OBJECT_LIST Object = malloc( sizeof( ALLOCATED_OBJECT_LIST ) + Sz );
  if( !Object )
  {
    return NULL;
  }

  Object->Mark = 0;
  Object->ObjectType = Type;
  Object->Length = Sz;  

  Object->NextObject = gAlloctedObjects;
  gAlloctedObjects = Object;
  
  return (void*)(Object + 1); // only return their allocated structure not ours
}
#else 
void* 
GcMalloc( 
    uint64_t Sz,
    uint8_t Type
)
{
  return malloc( Sz );
}
#endif 


/* A 1 dimensional array */
elt* allocate1(int64_t dim1 ) {
  elt* x = GcMalloc(S*(dim1+1), OBJECT_INT_ARRAY );
  for (unsigned long i = 0; i < dim1; i++)
    x[i+1].num = 0;
  x[0].num = dim1;
  return x;
}

/* A 2 dimensional array is an array of arrays */
elt* allocate2(int64_t dim1, int64_t dim2 ) {
  GcScan = false;
  elt* x = GcMalloc(S*(dim1+1), OBJECT_PTR_ARRAY );
  for (unsigned long i = 0; i < dim1; i++) {
    elt* y = GcMalloc(S*(dim2+1), OBJECT_INT_ARRAY  );
    x[i+1].ptr = y;
    for (int64_t j = 0; j < dim2; j++)
      y[j+1].num = 0;
    y[0].num = dim2;
  }
  x[0].num = dim1;
  GcScan = true;
#if _ENABLE_GC
  GcMarkAndSweep();
#endif
  return x;
}

/* Allocate dimensions dim to num_dim where the length of each dimension is
 * given by the list dims[] */
elt* allocate_n_help(int64_t dim, int64_t num_dim, int64_t *dims ) {
  if (dim == num_dim - 1)
  {
    return allocate1(dims[dim] );
  }
  else {
    elt* x = GcMalloc(S*(dims[dim]+1), OBJECT_PTR_ARRAY );
    for (unsigned long i = 0; i < dims[dim]; i++) {
      x[i+1].ptr = allocate_n_help(dim+1, num_dim, dims);
    }
    x[0].num = dims[dim];
    return x;
  }
}

elt* allocate_n(int64_t num_dim, int64_t *dims) {
  // dont want to scan while it is still allocating memory for array
#if _ENABLE_GC
  GcScan = false;
  elt* x = allocate_n_help(0, num_dim, dims );
  GcMarkAndSweep();
  GcScan = true;
  return x;
#else 
  return allocate_n_help(0, num_dim, dims );
#endif
}

elt* allocate3(int64_t dim1, int64_t dim2, int64_t dim3) {
  int64_t dims[] = {dim1, dim2, dim3};
  return allocate_n(3, dims);
}

elt* allocate4(int64_t dim1, int64_t dim2, int64_t dim3, int64_t dim4) {
  int64_t dims[] = {dim1, dim2, dim3, dim4};
  return allocate_n(4, dims);
}

elt* allocate5(int64_t dim1, int64_t dim2, int64_t dim3, int64_t dim4, int64_t dim5) {
  int64_t dims[] = {dim1, dim2, dim3, dim4, dim5};
  return allocate_n(5, dims);
}

elt* allocate6(int64_t dim1, int64_t dim2, int64_t dim3, int64_t dim4, int64_t dim5, int64_t dim6) {
  int64_t dims[] = {dim1, dim2, dim3, dim4, dim5, dim6};
  return allocate_n(6, dims);
}

elt* allocate7(int64_t dim1, int64_t dim2, int64_t dim3, int64_t dim4, int64_t dim5, int64_t dim6, int64_t dim7) {
  int64_t dims[] = {dim1, dim2, dim3, dim4, dim5, dim6, dim7};
  return allocate_n(7, dims);
}

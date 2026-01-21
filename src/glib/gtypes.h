//
// Created by owais on 1/21/2026.
//

#ifndef GTYPES_H
#define GTYPES_H

typedef int gint;

typedef uint8_t guint8;
typedef uint32_t guint32;
typedef uint64_t guint64;

#define GINT_TO_POINTER(i) ((void *)(intptr_t)(i))
#define GPOINTER_TO_INT(p) ((int)(intptr_t)(p))

#define GUINT_TO_POINTER(i) ((void *)(uintptr_t)(i))
#define GPOINTER_TO_UINT(p) ((int)(uintptr_t)(p))

#endif //GTYPES_H

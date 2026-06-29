/*
 * Copyright (c) 2015-2019 Dubalu LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#pragma once

// Branch-prediction hints. Self-contained: use __builtin_expect when the
// compiler is known to support it (GCC/Clang and compatibles), otherwise fall
// back to a plain passthrough. No config.h required.
//
// Xapiand's in-tree "likely.h" guards __builtin_expect behind a generated
// HAVE___BUILTIN_EXPECT; this standalone copy detects the builtin directly with
// __has_builtin (and the GCC fallback) so the extraction has no config.h
// coupling. http_parser.c includes this for the likely()/unlikely() macros.

#if defined(__has_builtin)
#  if __has_builtin(__builtin_expect)
#    define HTTP_PARSER_HAVE_BUILTIN_EXPECT 1
#  endif
#elif defined(__GNUC__)
#  define HTTP_PARSER_HAVE_BUILTIN_EXPECT 1
#endif

#ifdef HTTP_PARSER_HAVE_BUILTIN_EXPECT
#define likely(x) (__builtin_expect(!!(x), 1))
#define unlikely(x) (__builtin_expect(!!(x), 0))
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

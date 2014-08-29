/*
 Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
 This is a plugin of DECAF. You can redistribute and modify it
 under the terms of BSD license but it is made available
 WITHOUT ANY WARRANTY. See the top-level COPYING file for more details.

 For more information about DECAF and other softwares, see our
 web site at:
 http://sycurelab.ecs.syr.edu/

 If you have any questions about DECAF,please post it on
 http://code.google.com/p/decaf-platform/
 */
/**
 * @author Xunchao Hu, Heng Yin
 * @date Jan 24 2013
 */

#include <sys/time.h>
extern "C"
{
}
#include <stdio.h>
#include <inttypes.h>

extern "C" void publicbundle_cleanup_internal();

void publicbundle_cleanup_internal() {
	fprintf(stderr, "publicbundle is cleaned\n");

}

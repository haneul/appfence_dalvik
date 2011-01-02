/*
 * Copyright (C) 2009 ?
 * //Copyright (C) 2009 The Android Open Source Project
 * FIXME: What should the copyright be?
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * dalvik.system.Taint
 */
#include "Dalvik.h"
#include "native/InternalNativePriv.h"
#include "attr/xattr.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <cutils/process_name.h>
#include <cutils/sockets.h>
#include <policy_client.h>

#define TAINT_XATTR_NAME "user.taint"
typedef char byte;

/*
 * public static void addTaintString(String str, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintString(const u4* args,
    JValue* pResult)
{
    StringObject *strObj = (StringObject*) args[0];
    u4 tag = args[1];
    ArrayObject *value = NULL;
    
    if (strObj) {
	value = (ArrayObject*) dvmGetFieldObject((Object*)strObj,
				    gDvm.offJavaLangString_value);
	value->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static void addTaintObjectArray(Object[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintObjectArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
	arr->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static void addTaintBooleanArray(boolean[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintBooleanArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
	arr->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static void addTaintCharArray(char[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintCharArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
	arr->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static void addTaintByteArray(byte[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintByteArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
	arr->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static void addTaintIntArray(int[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintIntArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
	arr->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static void addTaintShortArray(short[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintShortArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
	arr->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static void addTaintLongArray(long[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintLongArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
	arr->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static void addTaintFloatArray(float[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintFloatArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
	arr->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static void addTaintDoubleArray(double[] array, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintDoubleArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 tag = args[1];
    if (arr) {
	arr->taint.tag |= tag;
    }
    RETURN_VOID();
}

/*
 * public static boolean addTaintBoolean(boolean val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintBoolean(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];	 /* the tag to add */
    u4* rtaint = (u4*) &args[2]; /* pointer to return taint tag */
    u4 vtaint  = args[3];	 /* the existing taint tag on val */
    *rtaint = (vtaint | tag);
    RETURN_BOOLEAN(val);
}

/*
 * public static char addTaintChar(char val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintChar(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];         /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];	  /* the existing taint tag on val */
    *rtaint = (vtaint | tag);
    RETURN_CHAR(val);
}

/*
 * public static char addTaintByte(byte val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintByte(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];         /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];	  /* the existing taint tag on val */
    *rtaint = (vtaint | tag);
    RETURN_BYTE(val);
}

/*
 * public static int addTaintInt(int val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintInt(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];	  /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];	  /* the existing taint tag on val */
    *rtaint = (vtaint | tag);
    RETURN_INT(val);
}

/*
 * public static long addTaintLong(long val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintLong(const u4* args,
    JValue* pResult)
{
    u8 val;
    u4 tag     = args[2];	     /* the tag to add */
    u4* rtaint = (u4*) &args[3];     /* pointer to return taint tag */
    u4 vtaint  = args[4];	     /* the existing taint tag on val */
    memcpy(&val, &args[0], 8);	     /* EABI prevents direct store */
    *rtaint = (vtaint | tag);
    RETURN_LONG(val);
}

/*
 * public static float addTaintFloat(float val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintFloat(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];	  /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];	  /* the existing taint tag on val */
    *rtaint = (vtaint | tag);
    RETURN_INT(val);		  /* Be opaque; RETURN_FLOAT doesn't work */
}

/*
 * public static double addTaintDouble(double val, int tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintDouble(const u4* args,
    JValue* pResult)
{
    u8 val;
    u4 tag     = args[2];	     /* the tag to add */
    u4* rtaint = (u4*) &args[3];     /* pointer to return taint tag */
    u4 vtaint  = args[4];	     /* the existing taint tag on val */
    memcpy(&val, &args[0], 8);	     /* EABI prevents direct store */
    *rtaint = (vtaint | tag);
    RETURN_LONG(val);		     /* Be opaque; RETURN_DOUBLE doesn't work */
}

/*
 * public static int getTaintString(String str)
 */
static void Dalvik_dalvik_system_Taint_getTaintString(const u4* args,
    JValue* pResult)
{
    StringObject *strObj = (StringObject*) args[0];
    ArrayObject *value = NULL;

    if (strObj) {
	value = (ArrayObject*) dvmGetFieldObject((Object*)strObj,
				    gDvm.offJavaLangString_value);
	RETURN_INT(value->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintObjectArray(Object[] obj)
 */
static void Dalvik_dalvik_system_Taint_getTaintObjectArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintBooleanArray(boolean[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintBooleanArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintCharArray(char[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintCharArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintByteArray(byte[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintByteArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintIntArray(int[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintIntArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintShortArray(short[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintShortArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintLongArray(long[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintLongArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintFloatArray(float[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintFloatArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintDoubleArray(double[] array)
 */
static void Dalvik_dalvik_system_Taint_getTaintDoubleArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else{ 
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getTaintBoolean(boolean val)
 */
static void Dalvik_dalvik_system_Taint_getTaintBoolean(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintChar(char val)
 */
static void Dalvik_dalvik_system_Taint_getTaintChar(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintByte(byte val)
 */
static void Dalvik_dalvik_system_Taint_getTaintByte(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintInt(int val)
 */
static void Dalvik_dalvik_system_Taint_getTaintInt(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintLong(long val)
 */
static void Dalvik_dalvik_system_Taint_getTaintLong(const u4* args,
    JValue* pResult)
{
    // args[0:1] = the value
    // args[2] = the return taint
    u4 tag = args[3]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintFloat(float val)
 */
static void Dalvik_dalvik_system_Taint_getTaintFloat(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintDouble(long val)
 */
static void Dalvik_dalvik_system_Taint_getTaintDouble(const u4* args,
    JValue* pResult)
{
    // args[0:1] = the value
    // args[2] = the return taint
    u4 tag = args[3]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getTaintRef(Object obj)
 */
static void Dalvik_dalvik_system_Taint_getTaintRef(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

static u4 getTaintXattr(int fd)
{
    int ret;
    u4 buf;
    u4 tag = TAINT_CLEAR;

    ret = fgetxattr(fd, TAINT_XATTR_NAME, &buf, sizeof(buf)); 
    if (ret > 0) {
	tag = buf;
    } else {
	if (errno == ENOATTR) {
	    /* do nothing */
	} else if (errno == ERANGE) {
	    LOGW("TaintLog: fgetxattr(%d) contents to large", fd);
	} else if (errno == ENOTSUP) {
	    /* XATTRs are not supported. No need to spam the logs */
	} else {
        /* There's a bug with this when checking taint on logcat file or
         * something... 
         */
        //LOGW("TaintLog: fgetxattr(%d): unknown error code %d", fd, errno);
	}
    }

    return tag;
}

static void setTaintXattr(int fd, u4 tag)
{
    int ret;

    ret = fsetxattr(fd, TAINT_XATTR_NAME, &tag, sizeof(tag), 0);

    if (ret < 0) {
	if (errno == ENOSPC || errno == EDQUOT) {
	    LOGW("TaintLog: fsetxattr(%d): not enough room to set xattr", fd);
	} else if (errno == ENOTSUP) {
	    /* XATTRs are not supported. No need to spam the logs */
	} else {
	    LOGW("TaintLog: fsetxattr(%d): unknown error code %d", fd, errno);
	}
    }

}

/*
 * public static int getTaintFile(int fd)
 */
static void Dalvik_dalvik_system_Taint_getTaintFile(const u4* args,
    JValue* pResult)
{
    u4 tag;
    int fd = (int)args[0]; // args[0] = the file descriptor
    // args[1] = the return taint
    // args[2] = fd taint
  
    tag = getTaintXattr(fd);

    if (tag) {
	LOGI("TaintLog: getTaintFile(%d) = 0x%08x", fd, tag);
    }
   
    RETURN_INT(tag);
}

/*
 * public static int addTaintFile(int fd, u4 tag)
 */
static void Dalvik_dalvik_system_Taint_addTaintFile(const u4* args,
    JValue* pResult)
{
    u4 otag;
    int fd = (int)args[0]; // args[0] = the file descriptor
    u4 tag = args[1];      // args[1] = the taint tag
    // args[2] = the return taint
    // args[3] = fd taint
    // args[4] = tag taint
    
    otag = getTaintXattr(fd);

    if (tag) {
	LOGI("TaintLog: addTaintFile(%d): adding 0x%08x to 0x%08x = 0x%08x",
		fd, tag, otag, tag | otag);
    }

    setTaintXattr(fd, tag | otag);

    RETURN_VOID();
}

/*
 * public static void log(String msg)
 */
static void Dalvik_dalvik_system_Taint_log(const u4* args,
    JValue* pResult)
{
    StringObject* msgObj = (StringObject*) args[0];
    int i;
    char *msg;

    if (msgObj == NULL) {
	dvmThrowException("Ljava/lang/NullPointerException;", NULL);
	RETURN_VOID();
    }

    msg = dvmCreateCstrFromString(msgObj);
    for (i = 0; i < strlen(msg); i++) {
        /* Replace unprintable characters with spaces:
         *   http://www.columbia.edu/kermit/ascii.html */
        if ((int)(msg[i]) < 32) {
            msg[i] = ' ';
        } 
    }
    LOGW("TaintLog: %s", msg);
    char *curmsg = msg;
    while(strlen(curmsg) > 1013) {
        curmsg = curmsg+1013;
        LOGW("%s", curmsg);
    }
    free(msg);

    RETURN_VOID();
}

/*
 * public static void logPathFromFd(int fd)
 */
static void Dalvik_dalvik_system_Taint_logPathFromFd(const u4* args,
    JValue* pResult)
{
    int fd = (int) args[0];
    pid_t pid;
    char ppath[20]; // these path lengths should be enough
    char rpath[80];
    int err;


    pid = getpid();
    snprintf(ppath, 20, "/proc/%d/fd/%d", pid, fd);
    err = readlink(ppath, rpath, 80);
    if (err >= 0) {
	LOGW("TaintLog: fd %d -> %s", fd, rpath);
    } else {
	LOGW("TaintLog: error finding path for fd %d", fd);
    }

    RETURN_VOID();
}

/*
 * public static void logPeerFromFd(int fd)
 */
static void Dalvik_dalvik_system_Taint_logPeerFromFd(const u4* args,
    JValue* pResult)
{
    int fd = (int) args[0];

    LOGW("TaintLog: logPeerFromFd not yet implemented");

    RETURN_VOID();
}

/*
 * public static int removeTaintInt(int val, int tag)
 */
static void Dalvik_dalvik_system_Taint_removeTaintInt(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 tag     = args[1];	        /* the tag to remove */
    u4* rtaint = (u4*) &args[2];    /* pointer to return taint tag */
    u4 vtaint  = args[3];	        /* the existing taint tag on val */
    *rtaint = (vtaint & (~tag));    /* AND existing tag with NOT of tag to
                                       remove */
    RETURN_INT(val);
}

/**
 * File descriptors for sockets that connect to "policyd" daemon server
 * that makes exposure policy decisions. policy_update_sockfd should only
 * be used by the Settings app (this is / should be / will be enforced by
 * the user+group settings of the socket); policy_sockfd is used by all
 * other apps.
 * Initialized to -1 to indicate that we haven't connected yet.
 */
static int policy_update_sockfd = -1;
static int policy_sockfd = -1;

/**
 * private static void setEnforcePolicyImpl(boolean newSetting);
 *
 * See dalvik/vm/native/dalvik_system_VMDebug.c for examples of how to "unpack"
 * the FileDesciptor object, etc.
 *
 * TODO: this should return an error code, not void.
 */
static void Dalvik_dalvik_system_Taint_setEnforcePolicyImpl(const u4* args,
    JValue* pResult)
{
    int ret = 0;
    policy_req request;
    policy_resp response;
    int request_code, response_code;
    u4 newSetting;

    LOGW("phornyac: setEnforcePolicyImpl: entered");
    newSetting = args[0];
    LOGW("phornyac: setEnforcePolicyImpl: newSetting=%d", newSetting);

    /* Connect to the policyd server, if we haven't already: */
    if (policy_update_sockfd == -1) {
        LOGW("phornyac: setEnforcePolicyImpl: policy_update_sockfd "
                "uninitialized, calling socket_local_client(%s, %d, %d)",
                POLICYD_UPDATESOCK, POLICYD_NSPACE, POLICYD_SOCKTYPE);
        ret = socket_local_client(POLICYD_UPDATESOCK, POLICYD_NSPACE,
                POLICYD_SOCKTYPE);
        if (ret == -1) {
            LOGW("phornyac: setEnforcePolicyImpl: socket_local_connect() "
                    "failed with ret=%d", ret);
        } else {
            policy_update_sockfd = ret;
            LOGW("phornyac: setEnforcePolicyImpl: socket_local_connect() "
                    "succeeded, setting policy_update_sockfd=%d",
                    policy_update_sockfd);
        }
    } else {
        LOGW("phornyac: setEnforcePolicyImpl: policy_update_sockfd was "
                "already set to %d",
                policy_update_sockfd);
    }

    /* Set up the policy request: */
    if (newSetting == 0) {
        LOGW("phornyac: setEnforcePolicyImpl: newSetting is 0, so using "
                "request_code POLICY_UPDATE_DISABLE");
        request_code = POLICY_UPDATE_DISABLE;
    } else {
        LOGW("phornyac: setEnforcePolicyImpl: newSetting is nonzero, so using "
                "request_code POLICY_UPDATE_ENABLE");
        request_code = POLICY_UPDATE_ENABLE;
    }
    ret = construct_policy_req(&request, request_code, NULL, NULL, 0);
    if (ret < 0) {
        LOGW("phornyac: setEnforcePolicyImpl: construct_policy_req() "
                "returned error=%d, returning void", ret);
        RETURN_VOID();
    }
    LOGW("phornyac: setEnforcePolicyImpl: construct_policy_req() "
            "returned ok");

    /* Send the request to the policyd server and get its response: */
    LOGW("phornyac: setEnforcePolicyImpl: calling send_policy_request() "
            "on policy_update_sockfd=%d", policy_update_sockfd);
    ret = send_policy_request(policy_update_sockfd, &request, &response);
    if (ret < 0) {
        LOGW("phornyac: setEnforcePolicyImpl: send_policy_request() "
                "returned error=%d, returning void", ret);
        RETURN_VOID();
    }
    LOGW("phornyac: setEnforcePolicyImpl: send_policy_request() "
            "returned ok, printing response:");
    print_policy_resp(&response);

    response_code = response.response_code;
    if (response_code != POLICY_RESP_SUCCESS) {
        LOGW("phornyac: setEnforcePolicyImpl: got unexpected response code "
                "%d, returning void!!!", response_code);
        RETURN_VOID();
    }
    LOGW("phornyac: setEnforcePolicyImpl: got POLICY_RESP_SUCCESS, "
            "returning void");
    RETURN_VOID();
}

static void test_longest_LOG_message() {
    unsigned int low = 8;
    unsigned int high = 14;
    unsigned int n;
    unsigned int i;
    unsigned int size;
    char *buf;

    LOGW("phornyac: test_longest_LOG_message: entered");
    /* Example: 2^4 is 16, which is 10000 in binary. */
    size = 1;
    for (i = 0; i < low; i++) {
        size = size << 1;
    }

    if (high < low)
        return;
    
    for (n = low; n <= high; n++) {
        buf = malloc((size*sizeof(char)));
        for (i = 0; i < size-1; i++) {
            buf[i] = (char)((i%10) + 48);
        }
        buf[size-1] = '\0';
        LOGW("phornyac: test_longest_LOG_message: attempting to print "
                "log message of size %d bytes", size);
        LOGW("%s", buf);
        free(buf);
        size = size << 1;
    }
}

#define MAX_LOG_SIZE 1024
static void Dalvik_dalvik_system_Taint_printByteArrayImpl(const u4* args,
    JValue* pResult)
{
    int len, chunks, i, j, k;
    char *data;
    char dataStr[MAX_LOG_SIZE];
    ArrayObject *dataObj = (ArrayObject *) args[0];

    /* My empirical testing has determined that LOGW will print
     * up to 1024 bytes of a character buffer that it is passed;
     * it will also prepend the tag and process id, but these do
     * not subtract from the 1024. Therefore, print the message
     * in 1024 byte chunks; null-zeros are not necessary until
     * the last chunk, and even then, we don't bother with the
     * final null-zero if the message is exactly a multiple of
     * 1024 bytes (which isn't uncommon for network send/receives).
     */
    if (dataObj) {
        len = dataObj->length;
        chunks = (len / MAX_LOG_SIZE);
        if (len % MAX_LOG_SIZE != 0)
            chunks++;
        LOGW("phornyac: printByteArrayImpl: printing array of size %d "
                "bytes in %d 1024-byte chunks", len, chunks);
        data = (char *) dataObj->contents;
        i = 0;
        /* i indexes into the byte array, "data";
         * j indexes into the char array, "dataStr".
         * This double for-loop isn't the clearest way to do this,
         * but oh well... */
        for (k = 0; k < chunks; k++) {
            for (j = 0; j < MAX_LOG_SIZE; j++) {
                /* Replace unprintable characters with spaces:
                 *   http://www.columbia.edu/kermit/ascii.html */
                if ((int)(data[i]) < 32) {
                    dataStr[j] = ' ';
                } else {
                    dataStr[j] = data[i];
                }
                i++;
                if (i > len) {
                    if (j < MAX_LOG_SIZE - 1) {
                        dataStr[j+1] = '\0';
                    }
                    j = MAX_LOG_SIZE;  //break
                }
            }
            LOGW("%s", dataStr);
        }
    } else {
        LOGW("phornyac: printByteArrayImpl: dataObj is null!!! Returning.");
    }
}

/**
 * private static boolean allowExposeNetworkImpl(FileDescriptor fd, byte[] data);
 *
 * See dalvik/vm/native/dalvik_system_VMDebug.c for examples of how to "unpack"
 * the FileDesciptor object, etc.
 */
static void Dalvik_dalvik_system_Taint_allowExposeNetworkImpl(const u4* args,
    JValue* pResult)
{
    LOGW("phornyac: allowExposeNetworkImpl(): entered");
    int ret = 0;
    unsigned int bytes_read;
    int read_ret;
    size_t msg_size;
    byte *buf;
    policy_req policy_request;
    policy_resp policy_response;
    DataObject *destFdObj = (DataObject *) args[0];
    ArrayObject *dataObj = (ArrayObject *) args[1];

    /* Check that fd is not null (will check arr later): */
    if (destFdObj == NULL) {
        dvmThrowException("Ljava/lang/NullPointerException;", NULL);
        RETURN_BOOLEAN(false);
    }

    /* Connect to the policyd server, if we haven't already: */
    if (policy_sockfd == -1) {
        LOGW("phornyac: allowExposeNetworkImpl(): policy_sockfd uninitialized, "
                "calling socket_local_client(%s, %d, %d)",
                POLICYD_SOCK, POLICYD_NSPACE, POLICYD_SOCKTYPE);
        ret = socket_local_client(POLICYD_SOCK, POLICYD_NSPACE, POLICYD_SOCKTYPE);
        if (ret == -1) {
            LOGW("phornyac: allowExposeNetworkImpl(): socket_local_connect() "
                    "failed with ret=%d", ret);
        } else {
            policy_sockfd = ret;
            LOGW("phornyac: allowExposeNetworkImpl(): socket_local_connect() "
                    "succeeded, setting policy_sockfd=%d", policy_sockfd);
        }
    } else {
        LOGW("phornyac: allowExposeNetworkImpl(): policy_sockfd already "
                "connected to %d", policy_sockfd);
    }

    /* Get the destination name (IP address) from the destination socket fd: */
    LOGW("phornyac: allowExposeNetworkImpl(): getting dvm fields");
    InstField *hasNameField = dvmFindInstanceField(destFdObj->obj.clazz,
            "hasName", "Z");  //signature for boolean is Z
    InstField *nameField = dvmFindInstanceField(destFdObj->obj.clazz,
            "name", "Ljava/lang/String;");  //signature for String is Ljava/lang/String;, I think
            //(This seems to work; but use something else to get an object/pointer?? Just "L"?)
    if ((hasNameField == NULL) || (nameField == NULL)) {
        dvmThrowException("Ljava/lang/NoSuchFieldException;",
                "couldn't find hasName or name field in FileDescriptor");
        RETURN_BOOLEAN(false);
    }
    bool hasName = dvmGetFieldBoolean(&destFdObj->obj,
            hasNameField->byteOffset);
    StringObject *destNameObj =
        (StringObject *) dvmGetFieldObject(&destFdObj->obj,
                nameField->byteOffset);
        //Is this right??? Get String or char* directly?? Seems to work...
    char *destName = dvmCreateCstrFromString(destNameObj);

    /* Get the taint tag of the data array: */
    u4 tag = TAINT_CLEAR;
    if (dataObj) {
        tag = dataObj->taint.tag;
            /* See getTaintByteArray() for this example */
            /* Actually, is there a way to call
             * Dalvik_dalvik_system_Taint_getTaintByteArray() or something
             * instead, to avoid code duplication??
             */
    } else {
        /* Do nothing: assume TAINT_CLEAR if byte[] is null */
        LOGW("phornyac: allowExposeNetworkImpl(): dataObj is null, "
                "expected??");
    }

    /* Get the name of the calling process: */
    const char *processName = get_process_name();

    LOGW("phornyac: allowExposeNetworkImpl(): calling "
            "construct_policy_req()");
    ret = construct_policy_req(&policy_request, POLICY_REQ_QUERY,
            processName, destName, tag);
    if (ret < 0) {
        LOGW("phornyac: allowExposeNetworkImpl(): construct_policy_req() "
                "returned ret=%d, returning false", ret);
        RETURN_BOOLEAN(false);
    }
    LOGW("phornyac: allowExposeNetworkImpl(): construct_policy_req() "
            "returned %d", ret);
    print_policy_req(&policy_request);

    LOGW("phornyac: allowExposeNetworkImpl(): calling "
            "send_policy_request()");
    ret = send_policy_request(policy_sockfd, &policy_request,
            &policy_response);
    if (ret < 0) {
        LOGW("phornyac: allowExposeNetworkImpl(): send_policy_request() "
                "returned error %d", ret);
        LOGW("phornyac: allowExposeNetworkImpl(): closing policy_sockfd and "
                "returning false");
        close(policy_sockfd);
        policy_sockfd = -1;
        RETURN_BOOLEAN(false);
    }
    LOGW("phornyac: allowExposeNetworkImpl(): send_policy_request() "
            "returned success, response code=%d",
            policy_response.response_code);

    LOGW("phornyac: allowExposeNetworkImpl(): switching on response code");
    switch (policy_response.response_code) {
    case POLICY_RESP_ALLOW:
        LOGW("phornyac: allowExposeNetworkImpl(): case POLICY_RESP_ALLOW, "
                "returning true");
        RETURN_BOOLEAN(true);
        break;
    case POLICY_RESP_BLOCK:
        LOGW("phornyac: allowExposeNetworkImpl(): case POLICY_RESP_BLOCK, "
                "returning false");
        RETURN_BOOLEAN(false);
        break;
    default:
        LOGW("phornyac: allowExposeNetworkImpl(): default case!?!, "
                "returning false");
        RETURN_BOOLEAN(false);
        break;
    }
    LOGW("phornyac: allowExposeNetworkImpl(): reached end, shouldn't be here, "
            "returning false");
    RETURN_BOOLEAN(false);
}

const DalvikNativeMethod dvm_dalvik_system_Taint[] = {
    { "addTaintString",  "(Ljava/lang/String;I)V",
        Dalvik_dalvik_system_Taint_addTaintString},
    { "addTaintObjectArray",  "([Ljava/lang/Object;I)V",
        Dalvik_dalvik_system_Taint_addTaintObjectArray},
    { "addTaintBooleanArray",  "([ZI)V",
        Dalvik_dalvik_system_Taint_addTaintBooleanArray},
    { "addTaintCharArray",  "([CI)V",
        Dalvik_dalvik_system_Taint_addTaintCharArray},
    { "addTaintByteArray",  "([BI)V",
        Dalvik_dalvik_system_Taint_addTaintByteArray},
    { "addTaintIntArray",  "([II)V",
        Dalvik_dalvik_system_Taint_addTaintIntArray},
    { "addTaintShortArray",  "([SI)V",
        Dalvik_dalvik_system_Taint_addTaintShortArray},
    { "addTaintLongArray",  "([JI)V",
        Dalvik_dalvik_system_Taint_addTaintLongArray},
    { "addTaintFloatArray",  "([FI)V",
        Dalvik_dalvik_system_Taint_addTaintFloatArray},
    { "addTaintDoubleArray",  "([DI)V",
        Dalvik_dalvik_system_Taint_addTaintDoubleArray},
    { "addTaintBoolean",  "(ZI)Z",
        Dalvik_dalvik_system_Taint_addTaintBoolean},
    { "addTaintChar",  "(CI)C",
        Dalvik_dalvik_system_Taint_addTaintChar},
    { "addTaintByte",  "(BI)B",
        Dalvik_dalvik_system_Taint_addTaintByte},
    { "addTaintInt",  "(II)I",
        Dalvik_dalvik_system_Taint_addTaintInt},
    { "addTaintLong",  "(JI)J",
        Dalvik_dalvik_system_Taint_addTaintLong},
    { "addTaintFloat",  "(FI)F",
        Dalvik_dalvik_system_Taint_addTaintFloat},
    { "addTaintDouble",  "(DI)D",
        Dalvik_dalvik_system_Taint_addTaintDouble},
    { "getTaintString",  "(Ljava/lang/String;)I",
        Dalvik_dalvik_system_Taint_getTaintString},
    { "getTaintObjectArray",  "([Ljava/lang/Object;)I",
        Dalvik_dalvik_system_Taint_getTaintObjectArray},
    { "getTaintBooleanArray",  "([Z)I",
        Dalvik_dalvik_system_Taint_getTaintBooleanArray},
    { "getTaintCharArray",  "([C)I",
        Dalvik_dalvik_system_Taint_getTaintCharArray},
    { "getTaintByteArray",  "([B)I",
        Dalvik_dalvik_system_Taint_getTaintByteArray},
    { "getTaintIntArray",  "([I)I",
        Dalvik_dalvik_system_Taint_getTaintIntArray},
    { "getTaintShortArray",  "([S)I",
        Dalvik_dalvik_system_Taint_getTaintShortArray},
    { "getTaintLongArray",  "([J)I",
        Dalvik_dalvik_system_Taint_getTaintLongArray},
    { "getTaintFloatArray",  "([F)I",
        Dalvik_dalvik_system_Taint_getTaintFloatArray},
    { "getTaintDoubleArray",  "([D)I",
        Dalvik_dalvik_system_Taint_getTaintDoubleArray},
    { "getTaintBoolean",  "(Z)I",
        Dalvik_dalvik_system_Taint_getTaintBoolean},
    { "getTaintChar",  "(C)I",
        Dalvik_dalvik_system_Taint_getTaintChar},
    { "getTaintByte",  "(B)I",
        Dalvik_dalvik_system_Taint_getTaintByte},
    { "getTaintInt",  "(I)I",
        Dalvik_dalvik_system_Taint_getTaintInt},
    { "getTaintLong",  "(J)I",
        Dalvik_dalvik_system_Taint_getTaintLong},
    { "getTaintFloat",  "(F)I",
        Dalvik_dalvik_system_Taint_getTaintFloat},
    { "getTaintDouble",  "(D)I",
        Dalvik_dalvik_system_Taint_getTaintDouble},
    { "getTaintRef",  "(Ljava/lang/Object;)I",
        Dalvik_dalvik_system_Taint_getTaintRef},
    { "getTaintFile",  "(I)I",
        Dalvik_dalvik_system_Taint_getTaintFile},
    { "addTaintFile",  "(II)V",
        Dalvik_dalvik_system_Taint_addTaintFile},
    { "log",  "(Ljava/lang/String;)V",
        Dalvik_dalvik_system_Taint_log},
    { "logPathFromFd",  "(I)V",
        Dalvik_dalvik_system_Taint_logPathFromFd},
    { "logPeerFromFd",  "(I)V",
        Dalvik_dalvik_system_Taint_logPeerFromFd},
    { "removeTaintInt",  "(II)I",
        Dalvik_dalvik_system_Taint_removeTaintInt},
    { "setEnforcePolicyImpl",  "(Z)V",
        Dalvik_dalvik_system_Taint_setEnforcePolicyImpl},
    { "allowExposeNetworkImpl",  "(Ljava/io/FileDescriptor;[B)Z",
        Dalvik_dalvik_system_Taint_allowExposeNetworkImpl},
    { "printByteArrayImpl",  "([B)V",
        Dalvik_dalvik_system_Taint_printByteArrayImpl},
    { NULL, NULL, NULL },
};

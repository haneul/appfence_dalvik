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
#include <sqlite3.h>

#define TAINT_XATTR_NAME "user.taint"

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
    char *msg;

    if (msgObj == NULL) {
	dvmThrowException("Ljava/lang/NullPointerException;", NULL);
	RETURN_VOID();
    }

    msg = dvmCreateCstrFromString(msgObj);
    LOGW("TaintLog: %s", msg);
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
 * Persistent variables for storing SQLite database connection, etc.
 */
const char *dbFilename = "/data/data/com.android.browser/policy.db";
//const char *dbFilename = "/data/data/com.android.browser/databases/policy.db";
  //"Once created, the SQLite database is stored in the
  // /data/data/<package_name>/databases folder of an Android device"
  //"/data/policyDb" doesn't work, just creates an empty file
  //  neither does "/data/data/com.android.settings/shared_prefs/policy.db"
  //Any "scratch" locations where all apps have write access? Not really...
  //  /sqlite_stmt_journals
  //Shouldn't be any locations where all apps have write access, because
  //otherwise apps could use it for unprotected IPC.
  //Solution: need to move this code to a _centralized_ location!
  //  Context: needs to be "system" or "root" user, not "app_5", etc.
const char *dbTableName = "policy";
sqlite3 *policyDb = NULL;
bool policyHasChanged = false;
bool defaultAllow = true;        //XXX: set this from global prefs!
sqlite3_stmt *queryStmt = NULL;

/* These constants define table structure/columns: */
//const int COLUMNS = 3;
enum dbColumns {    //must start at 0 for indexing into database!
    SRC = 0,        //SQLITE_TEXT
    DEST,           //SQLITE_TEXT
    TAINT,          //SQLITE_INTEGER
    COLUMNS         //must always be last!!!
};

/**
 * Constructs a query string that gets the records/rows of the database matching
 * the given source application name. Returns pointer to a newly-allocated string
 * (which should be freed by the caller) on success, or returns NULL on failure.
 */
char *constructQueryString(const char *source) {
    int queryLen;
    char *queryString;
    const char *select = "SELECT";
    const char *columns = "*";
    const char *from = "FROM";
    const char *where = "WHERE";
 
    LOGW("phornyac: constructQueryString(): entered");
    /**
     * Construct the SQL query string:
     *   SELECT *
     *     FROM <table_name>
     *     WHERE src='<source>'
     * Wildcards: ??
     * Impt: taint may not match exactly!
     *   So, use the callback function for each gotten record to AND the taint
     *   from the database record with the current data taint! This means that
     *   we will "match" if any bit in current data taint tag matches any bit in
     *   taint tag stored in database.
     *     Do this for destination too???? Yes!
     *       So, just WHERE on the source!
     * http://www.w3schools.com/sql/sql_select.asp
     * http://www.w3schools.com/sql/sql_where.asp
     *   Use single quotes, i.e. SELECT * FROM Persons WHERE FirstName='Tove'
     * http://www.w3schools.com/sql/sql_and_or.asp
     */

    //XXX: should sanitize input to this function, or risk SQL injection attack!

    //const char *qs = "SELECT * FROM policy WHERE "
    //    "src='com.android.browser'";
    queryLen = strlen(select) + strlen(" ") + strlen(columns) + 
        strlen(" ") + strlen(from) +
        strlen(" ") + strlen(dbTableName) + strlen(" ") + strlen(where) +
        strlen(" src=\"") + strlen(source) + strlen("\"") + 1;
    queryString = (char *)malloc(queryLen * sizeof(char));
    snprintf(queryString, queryLen, "%s %s %s %s %s src=\"%s\"",
            select, columns, from, dbTableName, where, source);
    LOGW("phornyac: constructQueryString(): queryLen=%d, queryString=%s",
            queryLen, queryString);
    return queryString;
}

/* Prints the current database row. */
void printRow(sqlite3_stmt *stmt){
    const unsigned char *dbSrc;
    const unsigned char *dbDest;
    int dbTaint;

    /**
     * Get the values from the destination and taint tag columns:
     * http://sqlite.org/c3ref/column_blob.html
     */
    dbSrc = sqlite3_column_text(stmt, SRC);
    dbDest = sqlite3_column_text(stmt, DEST);
    dbTaint = sqlite3_column_int(stmt, TAINT);
 
    LOGW("phornyac: printRow(): dbSrc=%s, dbDest=%s, dbTaint=0x%X",
            dbSrc, dbDest, dbTaint);
}

/**
 * Returns true if the two destination IP addresses match.
 * XXX: enhance this function to consider wildcards/subnets!
 */
bool destinationMatch(const char *dest1, const char *dest2) {
    LOGW("phornyac: destinationMatch: dest1=%s, dest2=%s",
            dest1, dest2);
    return (strcmp(dest1, dest2) == 0);
}

/**
 * Returns true if the two taint tags "match," i.e. if they have any of the same
 * bits set.
 */
bool taintMatch(int taint1, int taint2) {
    LOGW("phornyac: taintMatch: taint1=0x%X, taint2=0x%X",
            taint1, taint2);
    if (taint1 & taint2) {
        return true;
    }
    return false;
}

/**
 * Function that is called for every database record that our query
 * returns. If we select the records based solely on the application name,
 * then this function should return true if the destination server and taint
 * of the data about to be transmitted BOTH match one of the records.
 */
bool checkRowForMatch(sqlite3_stmt *queryStmt, const char *dest, int taint) {
    const unsigned char *dbDest;
    int dbTaint;

    LOGW("phornyac: checkRowForMatch(): entered");

    /**
     * Get the values from the destination and taint tag columns:
     * http://sqlite.org/c3ref/column_blob.html
     */
    dbDest = sqlite3_column_text(queryStmt, DEST);
    if (dbDest == NULL) {
        LOGW("phornyac: checkRowForMatch(): dbDest got NULL, returning false!");
        return false;
    }
    dbTaint = sqlite3_column_int(queryStmt, TAINT);

    /* Return true if BOTH the destinations and the taints match: */
    if (destinationMatch(dest, (const char *)dbDest) && taintMatch(taint, dbTaint)) {
        LOGW("phornyac: checkRowForMatch(): returning true");
        return true;
    }
    LOGW("phornyac: checkRowForMatch(): returning false");
    return false;
}

/**
 * Adds the given (source, dest, taint) triple to the database table.
 * Returns 0 on success, negative on error.
 */
int insertDbRow(sqlite3 *db, const char *tableName, const char *source,
        const char *dest, int taint) {
    sqlite3_stmt *insertStmt;
    int len;
    int err;
    char *insertString;
    char taintString[32];
      //2^64 = 18446744073709551616, which is 20 digits

    LOGW("phornyac: insertDbRow(): entered");

    /**
     * Construct the INSERT string:
     *   INSERT INTO table_name VALUES (source, dest, taint)
     * See http://www.w3schools.com/sql/sql_insert.asp
     * XXX: not safe from injection attack???
     */
    const char *insertInto = "INSERT INTO";
    const char *values = "VALUES";
    /* Convert taint int to string: */
    snprintf(taintString, 32, "%x", taint);
    LOGW("phornyac: insertDbRow(): calculated taintString=%s, len=%d",
            taintString, strlen(taintString));
    len = strlen(insertInto) + strlen(" ") + strlen(tableName) + 
        strlen(" ") + strlen(values) + strlen(" (\"") + strlen(source) +
        strlen("\", \"") + strlen(dest) + strlen("\", \"") + strlen(taintString) +
        strlen("\")") + 1;
    insertString = malloc(len * sizeof(char));
    /* Must use quotes around column values inside () ! */
    snprintf(insertString, len, "%s %s %s (\"%s\", \"%s\", \"%s\")",
            insertInto, tableName, values, source, dest, taintString);
    LOGW("phornyac: insertDbRow(): constructed insertString=%s", insertString);

    /**
     * Prepare an SQLite statement with the INSERT string:
     * See http://sqlite.org/c3ref/prepare.html
     */
    LOGW("phornyac: insertDbRow(): calling sqlite3_prepare_v2()");
    err = sqlite3_prepare_v2(db, insertString, len, &insertStmt, NULL);
    free(insertString);
    if (err != SQLITE_OK) {
        LOGW("phornyac: insertDbRow(): sqlite3_prepare_v2() returned "
                "error: %s", sqlite3_errmsg(db));
        LOGW("phornyac: insertDbRow(): returning -1 due to errors");
        return -1;
    }

    /**
     * Execute the prepared statement:
     */
    LOGW("phornyac: insertDbRow(): calling sqlite3_step() to execute "
            "INSERT statement");
    err = sqlite3_step(insertStmt);
    if (err != SQLITE_DONE) {
        LOGW("phornyac: insertDbRow(): sqlite3_step() returned "
                "error: %s", sqlite3_errmsg(db));
        LOGW("phornyac: insertDbRow(): returning -1 due to errors");
        sqlite3_finalize(insertStmt);  //ignore return value
        return -1;
    }
 
    /* Finalize and return: */
    LOGW("phornyac: insertDbRow(): INSERT succeeded, finalizing and returning");
    err = sqlite3_finalize(insertStmt);
    if (err != SQLITE_OK) {
        LOGW("phornyac: insertDbRow(): sqlite3_finalize() returned "
                "error: %s", sqlite3_errmsg(db));
        LOGW("phornyac: insertDbRow(): returning -1 due to errors");
        return -1;
    }
    return 0;
}

/**
 * Checks the (source, dest, taint) triple against the currently selected
 * policy.
 * Returns: true if the current policy allows the data to be sent, false if
 *   the current policy denies the transmission or on error.
 */
bool doesPolicyAllow(const char *processName, const char *destName, int tag) {
    char *queryString;
    int queryLen;
    const char *columns="*";
    char *errmsg = NULL;
    bool match;
    bool retval = false;
    int err;
    //DEBUG:
    struct stat dbStat;

    LOGW("phornyac: doesPolicyAllow(): entered");
    LOGW("phornyac: doesPolicyAllow(): processName=%s, destName=%s, tag=%d",
            processName, destName, tag);

    /* Use snprintf() to generate db filename? */
    //...

    /**
     * Initialize the database connection if not already done:
     * http://sqlite.org/c3ref/open.html
     */
    if (policyDb == NULL) {
        LOGW("phornyac: doesPolicyAllow(): policyDb is NULL, initializing");

        //DEBUG (XXX: remove this):
        LOGW("phornyac: doesPolicyAllow(): calling stat for dbFilename=%s",
                dbFilename);
        err = stat(dbFilename, &dbStat);
        if (err) {
            if (errno == ENOENT) {
                LOGW("phornyac: doesPolicyAllow(): stat returned errno=ENOENT, "
                        "db file does not exist yet");
            } else {
                LOGW("phornyac: doesPolicyAllow(): stat returned other errno=%d",
                        errno);
            }
        } else {
            LOGW("phornyac: doesPolicyAllow(): stat succeeded, db file exists");
        }

        //XXX: figure out if this code is central, or if it's "instantiated"
        //  once per application...
        //Right now, it's instantiated once per application!
        //  Figure out a more central place to put it...
        LOGW("phornyac: doesPolicyAllow(): calling sqlite3_open(%s)",
                dbFilename);
        /**
         * The "standard" version of sqlite3_open() opens a database for reading
         * and writing, and creates it if it does not exist.
         * http://sqlite.org/c3ref/open.html
         */
        err = sqlite3_open(dbFilename, &policyDb);
        if ((err != SQLITE_OK) || (policyDb == NULL)) {
            if (policyDb == NULL) {
                LOGW("phornyac: doesPolicyAllow(): sqlite3_open() returned "
                        "NULL policyDb!");
            }
            LOGW("phornyac: doesPolicyAllow(): sqlite3_open() error message: "
                    "%s", sqlite3_errmsg(policyDb));
            policyDb = NULL;  /* set back to NULL so we'll retry after error */
            LOGW("phornyac: doesPolicyAllow(): returning false due to errors");
            retval = false;
            goto out;
        }
        LOGW("phornyac: doesPolicyAllow(): sqlite3_open() succeeded, policyDb=%p",
                policyDb);
        /* XXX: We never close the database connection: is this ok? */

        /**
         * Create the table:
         * See http://sqlite.org/lang_createtable.html
         * See http://sqlite.org/c3ref/exec.html
         */
        LOGW("phornyac: doesPolicyAllow(): creating table \"%s\"", dbTableName);
        //XXX: un-hard-code this!
        //XXX: put this in a separate function!
       err = sqlite3_exec(policyDb, "CREATE TABLE policy (src TEXT, dest TEXT, taint INTEGER)",
                NULL, NULL, &errmsg);
        LOGW("phornyac: doesPolicyAllow(): sqlite3_exec() returned");
        if (err) {
            if (errmsg) {
                /**
                 * "To avoid memory leaks, the application should invoke
                 *  sqlite3_free() on error message strings returned through the
                 *  5th parameter of of sqlite3_exec() after the error message
                 *  string is no longer needed. If the 5th parameter to
                 *  sqlite3_exec() is not NULL and no errors occur, then
                 *  sqlite3_exec() sets the pointer in its 5th parameter to NULL
                 *  before returning."
                 */
                LOGW("phornyac: doesPolicyAllow(): sqlite3_exec(CREATE TABLE) "
                        "returned error \"%s\", so returning false", errmsg);
                /**
                 * For some reason, when I open browser, then open maps app, I get this
                 * error from maps:
                 *   "W/dalvikvm(  475): phornyac: doesPolicyAllow(): sqlite3_exec(CREATE
                 *    TABLE) returned error "table policy already exists", so   returning
                 *    false
                 */
                sqlite3_free(errmsg);
            } else {
                LOGW("phornyac: doesPolicyAllow(): sqlite3_exec(CREATE TABLE) "
                        "returned error, errmsg=NULL");
            }
            policyDb = NULL;  /* set back to NULL so we'll retry after error */
            retval = false;
            goto out;
        }

        /* Add some simple rows to database / table for now: */
        LOGW("phornyac: doesPolicyAllow(): adding sample rows to database");
        err = insertDbRow(policyDb, dbTableName, "source1", "dest1", 0);
        err |= insertDbRow(policyDb, dbTableName, "source2", "dest2", 1);
        err |= insertDbRow(policyDb, dbTableName, "com.android.browser",
                "*", 255);
        err |= insertDbRow(policyDb, dbTableName, "com.android.browser",
                "72.14.213.99", 255);  //255 = 0xff
        //(DEBUG: Get all rows in a table: SELECT * FROM Persons)
        if (err) {
            LOGW("phornyac: doesPolicyAllow(): insertDbRow() returned error, "
                    "so returning false");
            policyDb = NULL;  /* set back to NULL so we'll retry after error */
            retval = false;
            goto out;
        }

    } else {
        LOGW("phornyac: doesPolicyAllow(): policyDb was not NULL");
    }

    /**
     * Check if the policy has changed, and if so, reload the database...
     * The policyHasChanged variable should be changed when the global policy
     * preferences are changed (or we may have to get/check the policy setting
     * here...)
     * XXX: implement this!
     */
    if (policyHasChanged) {
        LOGW("phornyac: doesPolicyAllow(): policyHasChanged is true, "
                "re-initializing");

        //Close database connection, remove table, re-create database?
        //Combine this with database initialization code above??
        LOGW("phornyac: doesPolicyAllow(): XXX: need to implement changed "
                "policy code!");
        policyHasChanged = false;
    } else {
        LOGW("phornyac: doesPolicyAllow(): policyHasChanged is false");
    }

    /**
     * Construct a query string to get all of the records matching the current
     * application name: 
     */
    queryString = constructQueryString(processName);  /* Don't forget to free! */
    if (queryString == NULL) {
        LOGW("phornyac: doesPolicyAllow(): constructQueryString returned NULL, "
                "so returning false");
        retval = false;
        goto out;
    }
    LOGW("phornyac: doesPolicyAllow(): constructQueryString returned string %s",
                queryString);
    queryLen = strlen(queryString);

    /**
     * Prepare the SQLite statement:
     * http://sqlite.org/c3ref/prepare.html
     */
    LOGW("phornyac: doesPolicyAllow(): calling sqlite3_prepare_v2()");
    err = sqlite3_prepare_v2(policyDb, queryString, queryLen + 1,
            &queryStmt, NULL);
    free(queryString);
    if (err != SQLITE_OK) {
        LOGW("phornyac: doesPolicyAllow(): sqlite3_prepare_v2() returned "
                "error: %s", sqlite3_errmsg(policyDb));
        LOGW("phornyac: doesPolicyAllow(): returning false due to errors");
        retval = false;
        goto out;
    }

    /**
     * Evaluate the SQL statement: call sqlite3_step() to get the next matching
     * record, then call checkRowForMatch() to see if the record matches the
     * current destination server and taint tag. Repeat until a match is found,
     * or until the statement evaluation is complete and sqlite3_step() returns
     * SQLITE_DONE.
     * If there is a match, we return
     * either true or false, depending on whether our default policy (in the
     * case of no matches) is to block or allow the data transmission.
     * http://sqlite.org/c3ref/step.html
     */
    LOGW("phornyac: doesPolicyAllow(): evaluating the statement by calling "
            "sqlite3_step() repeatedly");
    err = SQLITE_OK;
    while (err != SQLITE_DONE) {
        LOGW("phornyac: doesPolicyAllow(): calling sqlite3_step()");
        err = sqlite3_step(queryStmt);

        if (err == SQLITE_ROW) {
            printRow(queryStmt);
            match = checkRowForMatch(queryStmt, destName, tag);
            if (match) {
                /**
                 * If the default policy is to allow data transmission, then
                 * when there is a matching record in the policy database we
                 * should block the transmission, and vice-versa:
                 */
                if (defaultAllow) {
                    LOGW("phornyac: doesPolicyAllow(): found a match, setting "
                            "retval=false");
                    retval = false;
                } else {
                    LOGW("phornyac: doesPolicyAllow(): found a match, setting "
                            "retval=true");
                    retval = true;
                }
                goto finalize_and_out;
            } 
        } else if (err != SQLITE_DONE) {
            LOGW("phornyac: doesPolicyAllow(): sqlite3_step() returned "
                    "error: %s", sqlite3_errmsg(policyDb));
            LOGW("phornyac: doesPolicyAllow(): returning false due to errors");
            retval = false;
            goto finalize_and_out;
        }
    }

    /**
     * If we reach this code, the query returned no matching rows, so we
     * return true if the default policy is to allow transmission and false
     * if the default policy is to deny transmission:
     */
    if (defaultAllow) {
        LOGW("phornyac: doesPolicyAllow(): no match, setting retval=true");
        retval = true;
    } else {
        LOGW("phornyac: doesPolicyAllow(): no match, setting retval=false");
        retval = false;
    }

finalize_and_out:
    LOGW("phornyac: doesPolicyAllow(): finalizing queryStmt and returning");
    sqlite3_finalize(queryStmt);
    queryStmt = NULL;
      //XXX: optimize this function to re-use queryStmt??
out:
    return retval;
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
    DataObject *destFdObj = (DataObject *) args[0];
    ArrayObject *dataObj = (ArrayObject *) args[1];

    /* Check that fd is not null (will check arr later): */
    if (destFdObj == NULL) {
        dvmThrowException("Ljava/lang/NullPointerException;", NULL);
        RETURN_BOOLEAN(false);
    }

    /* Get the destination name (IP adress) from the socket fd: */
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

        /* Debugging: */
        /* contents is a byte[], so use char... right? */
        int len = dataObj->length;
        char *data = (char *) dataObj->contents;
        int size = 0;
        char dataStr[1024];
        while (data && (size < len) && (size < 1023)) {
            if (data[size] == '\0') {
                dataStr[size] = ' ';
            } else {
                dataStr[size] = data[size];
            }
            size++;
        }
        dataStr[size] = '\0';
        LOGW("phornyac: allowExposeNetworkImpl(): len=%d, dataStr=\"%s\"",
                len, dataStr);
    } else {
        /* Do nothing: assume TAINT_CLEAR if byte[] is null */
        LOGW("phornyac: allowExposeNetworkImpl(): dataObj is null, "
                "expected??");
    }

    /* Get the name of the calling process: */
    const char *processName = get_process_name();

    /* Now we have everything we need: */
    LOGW("phornyac: allowExposeNetworkImpl(): calling doesPolicyAllow() with "
            "source=%s, dest=%s, taint=0x%X", processName, destName, tag);

    /* Get and check policy: */
    RETURN_BOOLEAN(doesPolicyAllow(processName, destName, tag));

    //XXX: unreachable code, remove!
    if (tag & TAINT_LOCATION_GPS) {
        LOGW("phornyac: allowExposeNetworkImpl(): TAINT_LOCATION_GPS set, "
                "returning false");
        RETURN_BOOLEAN(false);
    } else if (tag & TAINT_LOCATION) {
        LOGW("phornyac: allowExposeNetworkImpl(): TAINT_LOCATION set, "
                "returning true for now");
        RETURN_BOOLEAN(true);
    }

    LOGW("phornyac: allowExposeNetworkImpl(): no checks failed, returning "
            "true");
    RETURN_BOOLEAN(true);
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
    { "allowExposeNetworkImpl",  "(Ljava/io/FileDescriptor;[B)Z",
        Dalvik_dalvik_system_Taint_allowExposeNetworkImpl},
    { NULL, NULL, NULL },
};

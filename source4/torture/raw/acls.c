/* 
   Unix SMB/CIFS implementation.

   test security descriptor operations

   Copyright (C) Andrew Tridgell 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "torture/torture.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"
#include "librpc/gen_ndr/lsa.h"
#include "libcli/util/clilsa.h"
#include "libcli/security/security.h"
#include "torture/util.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "torture/raw/proto.h"


#if 1 // Needed for fuse_file and fuse_dir test cases.
#include "libcli/ldap/ldap_client.h"
#include "utils/net.h"
#include "ads.h"
#include "param/param.h"
#include "system/filesys.h"
#endif

#define BASEDIR_NAME	"testsd"
#define BASEDIR "\\" BASEDIR_NAME

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		ret = false; \
		torture_result(tctx, TORTURE_FAIL, "(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		goto done; \
	}} while (0)

#define FAIL_UNLESS(__cond)					\
	do {							\
		if (__cond) {} else {				\
			ret = false; \
			torture_result(tctx, TORTURE_FAIL, "%s) condition violated: %s\n", \
			    __location__, #__cond); \
			goto done; \
		}						\
	} while(0)

#define CHECK_SECURITY_DESCRIPTOR(_sd1, _sd2) do { \
	if (!security_descriptor_equal(_sd1, _sd2)) { \
		torture_warning(tctx, "%s: security descriptors don't match!\n", __location__); \
		torture_warning(tctx, "got:\n"); \
		NDR_PRINT_DEBUG(security_descriptor, _sd1); \
		torture_warning(tctx, "expected:\n"); \
		NDR_PRINT_DEBUG(security_descriptor, _sd2); \
		ret = false; \
	} \
} while (0)

/*
 * Helper function to verify a security descriptor, by querying
 * and comparing against the passed in sd.
 * Copied to smb2_util_verify_sd() for SMB2.
 */
static bool verify_sd(TALLOC_CTX *tctx, struct smbcli_state *cli,
    int fnum, struct security_descriptor *sd)
{
	NTSTATUS status;
	bool ret = true;
	union smb_fileinfo q = {};

	if (sd) {
		q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
		q.query_secdesc.in.file.fnum = fnum;
		q.query_secdesc.in.secinfo_flags =
		    SECINFO_OWNER |
		    SECINFO_GROUP |
		    SECINFO_DACL;
		status = smb_raw_fileinfo(cli->tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);

		/* More work is needed if we're going to check this bit. */
		sd->type &= ~SEC_DESC_DACL_AUTO_INHERITED;

		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd);
	}

 done:
	return ret;
}

/*
 * Helper function to verify attributes, by querying
 * and comparing against the passed attrib.
 * Copied to smb2_util_verify_attrib() for SMB2.
 */
static bool verify_attrib(TALLOC_CTX *tctx, struct smbcli_state *cli,
    int fnum, uint32_t attrib)
{
	NTSTATUS status;
	bool ret = true;
	union smb_fileinfo q2 = {};

	if (attrib) {
		q2.standard.level = RAW_FILEINFO_STANDARD;
		q2.standard.in.file.fnum = fnum;
		status = smb_raw_fileinfo(cli->tree, tctx, &q2);
		CHECK_STATUS(status, NT_STATUS_OK);

		q2.standard.out.attrib &= ~FILE_ATTRIBUTE_ARCHIVE;

		if (q2.standard.out.attrib != attrib) {
			torture_warning(tctx, "%s: attributes don't match! "
			    "got %x, expected %x\n", __location__,
			    (uint32_t)q2.standard.out.attrib,
			    (uint32_t)attrib);
			ret = false;
		}
	}

 done:
	return ret;
}

/**
 * Test setting and removing a DACL.
 * Test copied to torture_smb2_setinfo() for SMB2.
 */
static bool test_sd(struct torture_context *tctx, struct smbcli_state *cli)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname = BASEDIR "\\sd.txt";
	bool ret = true;
	int fnum = -1;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_ace ace;
	struct security_descriptor *sd;
	struct dom_sid *test_sid;

	if (!torture_setup_dir(cli, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING SETFILEINFO EA_SET\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ | 
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = 
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd = q.query_secdesc.out.sd;

	torture_comment(tctx, "add a new ACE to the DACL\n");

	test_sid = dom_sid_parse_talloc(tctx, SID_NT_AUTHENTICATED_USERS);

	ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace.flags = 0;
	ace.access_mask = SEC_STD_ALL;
	ace.trustee = *test_sid;

	status = security_descriptor_dacl_add(sd, &ace);
	CHECK_STATUS(status, NT_STATUS_OK);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = q.query_secdesc.in.secinfo_flags;
	set.set_secdesc.in.sd = sd;

	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);
	FAIL_UNLESS(verify_sd(tctx, cli, fnum, sd));

	torture_comment(tctx, "remove it again\n");

	status = security_descriptor_dacl_del(sd, test_sid);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);
	FAIL_UNLESS(verify_sd(tctx, cli, fnum, sd));

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}


/*
  test using nttrans create to create a file with an initial acl set
  Test copied to test_create_acl() for SMB2.
*/
static bool test_nttrans_create_ext(struct torture_context *tctx,
				    struct smbcli_state *cli, bool test_dir)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname = BASEDIR "\\acl2.txt";
	bool ret = true;
	int fnum = -1;
	union smb_fileinfo q = {};
	struct security_ace ace;
	struct security_descriptor *sd;
	struct dom_sid *test_sid;
	uint32_t attrib =
	    FILE_ATTRIBUTE_HIDDEN |
	    FILE_ATTRIBUTE_SYSTEM |
	    (test_dir ? FILE_ATTRIBUTE_DIRECTORY : 0);
	NTSTATUS (*delete_func)(struct smbcli_tree *, const char *) =
	    test_dir ? smbcli_rmdir : smbcli_unlink;

	if (!torture_setup_dir(cli, BASEDIR))
		return false;

	io.generic.level = RAW_OPEN_NTTRANS_CREATE;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options =
	    test_dir ? NTCREATEX_OPTIONS_DIRECTORY : 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ | 
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	io.ntcreatex.in.sec_desc = NULL;
	io.ntcreatex.in.ea_list = NULL;

	torture_comment(tctx, "basic create\n");

	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "querying ACL\n");

	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = 
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd = q.query_secdesc.out.sd;

	status = smbcli_close(cli->tree, fnum);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = delete_func(cli->tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "adding a new ACE\n");
	test_sid = dom_sid_parse_talloc(tctx, SID_NT_AUTHENTICATED_USERS);

	ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace.flags = 0;
	ace.access_mask = SEC_STD_ALL;
	ace.trustee = *test_sid;

	status = security_descriptor_dacl_add(sd, &ace);
	CHECK_STATUS(status, NT_STATUS_OK);
	
	torture_comment(tctx, "creating with an initial ACL\n");

	io.ntcreatex.in.sec_desc = sd;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	
	FAIL_UNLESS(verify_sd(tctx, cli, fnum, sd));

	status = smbcli_close(cli->tree, fnum);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = delete_func(cli->tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "creating with attributes\n");

	io.ntcreatex.in.sec_desc = NULL;
	io.ntcreatex.in.file_attr = attrib;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	FAIL_UNLESS(verify_attrib(tctx, cli, fnum, attrib));

	status = smbcli_close(cli->tree, fnum);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = delete_func(cli->tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "creating with attributes and ACL\n");

	io.ntcreatex.in.sec_desc = sd;
	io.ntcreatex.in.file_attr = attrib;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	FAIL_UNLESS(verify_sd(tctx, cli, fnum, sd));
	FAIL_UNLESS(verify_attrib(tctx, cli, fnum, attrib));

	status = smbcli_close(cli->tree, fnum);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = delete_func(cli->tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "creating with attributes, ACL and owner\n");

	sd = security_descriptor_dacl_create(tctx,
					0, SID_WORLD, SID_BUILTIN_USERS,
					SID_WORLD,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
					0,
					NULL);

	io.ntcreatex.in.sec_desc = sd;
	io.ntcreatex.in.file_attr = attrib;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	FAIL_UNLESS(verify_sd(tctx, cli, fnum, sd));
	FAIL_UNLESS(verify_attrib(tctx, cli, fnum, attrib));

	status = smbcli_close(cli->tree, fnum);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = delete_func(cli->tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

 done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}

static bool test_nttrans_create_file(struct torture_context *tctx,
    struct smbcli_state *cli)
{
	torture_comment(tctx, "Testing nttrans create with sec_desc on files\n");

	return test_nttrans_create_ext(tctx, cli, false);
}

static bool test_nttrans_create_dir(struct torture_context *tctx,
    struct smbcli_state *cli)
{
	torture_comment(tctx, "Testing nttrans create with sec_desc on directories\n");

	return test_nttrans_create_ext(tctx, cli, true);
}

#define CHECK_ACCESS_FLAGS(_fnum, flags) do { \
	union smb_fileinfo _q; \
	_q.access_information.level = RAW_FILEINFO_ACCESS_INFORMATION; \
	_q.access_information.in.file.fnum = (_fnum); \
	status = smb_raw_fileinfo(cli->tree, tctx, &_q); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	if (_q.access_information.out.access_flags != (flags)) { \
		ret = false; \
		torture_result(tctx, TORTURE_FAIL, "(%s) Incorrect access_flags 0x%08x - should be 0x%08x\n", \
		       __location__, _q.access_information.out.access_flags, (flags)); \
		goto done; \
	} \
} while (0)

/*
  test using NTTRANS CREATE to create a file with a null ACL set
  Test copied to test_create_null_dacl() for SMB2.
*/
static bool test_nttrans_create_null_dacl(struct torture_context *tctx,
					  struct smbcli_state *cli)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname = BASEDIR "\\nulldacl.txt";
	bool ret = true;
	int fnum = -1;
	union smb_fileinfo q;
	union smb_setfileinfo s;
	struct security_descriptor *sd = security_descriptor_initialise(tctx);
	struct security_acl dacl;

	if (!torture_setup_dir(cli, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING SEC_DESC WITH A NULL DACL\n");

	io.generic.level = RAW_OPEN_NTTRANS_CREATE;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC
		| SEC_STD_WRITE_OWNER;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access =
		NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	io.ntcreatex.in.sec_desc = sd;
	io.ntcreatex.in.ea_list = NULL;

	torture_comment(tctx, "creating a file with a empty sd\n");
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags =
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * Testing the created DACL,
	 * the server should add the inherited DACL
	 * when SEC_DESC_DACL_PRESENT isn't specified
	 */
	if (!(q.query_secdesc.out.sd->type & SEC_DESC_DACL_PRESENT)) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, "DACL_PRESENT flag not set by the server!\n");
		goto done;
	}
	if (q.query_secdesc.out.sd->dacl == NULL) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, "no DACL has been created on the server!\n");
		goto done;
	}

	torture_comment(tctx, "set NULL DACL\n");
	sd->type |= SEC_DESC_DACL_PRESENT;

	s.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	s.set_secdesc.in.file.fnum = fnum;
	s.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	s.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &s);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "get the sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags =
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Testing the modified DACL */
	if (!(q.query_secdesc.out.sd->type & SEC_DESC_DACL_PRESENT)) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, "DACL_PRESENT flag not set by the server!\n");
		goto done;
	}
	if (q.query_secdesc.out.sd->dacl != NULL) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, "DACL has been created on the server!\n");
		goto done;
	}

	torture_comment(tctx, "try open for read control\n");
	io.ntcreatex.in.access_mask = SEC_STD_READ_CONTROL;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum,
		SEC_STD_READ_CONTROL | SEC_FILE_READ_ATTRIBUTE);
	smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

	torture_comment(tctx, "try open for write\n");
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum,
		SEC_FILE_WRITE_DATA | SEC_FILE_READ_ATTRIBUTE);
	smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

	torture_comment(tctx, "try open for read\n");
	io.ntcreatex.in.access_mask = SEC_FILE_READ_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum,
		SEC_FILE_READ_DATA | SEC_FILE_READ_ATTRIBUTE);
	smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

	torture_comment(tctx, "try open for generic write\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_WRITE;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum,
		SEC_RIGHTS_FILE_WRITE | SEC_FILE_READ_ATTRIBUTE);
	smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

	torture_comment(tctx, "try open for generic read\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_READ;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum,
		SEC_RIGHTS_FILE_READ | SEC_FILE_READ_ATTRIBUTE);
	smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

	torture_comment(tctx, "set DACL with 0 aces\n");
	ZERO_STRUCT(dacl);
	dacl.revision = SECURITY_ACL_REVISION_NT4;
	dacl.num_aces = 0;
	sd->dacl = &dacl;

	s.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	s.set_secdesc.in.file.fnum = fnum;
	s.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	s.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &s);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "get the sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags =
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Testing the modified DACL */
	if (!(q.query_secdesc.out.sd->type & SEC_DESC_DACL_PRESENT)) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, "DACL_PRESENT flag not set by the server!\n");
		goto done;
	}
	if (q.query_secdesc.out.sd->dacl == NULL) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, "no DACL has been created on the server!\n");
		goto done;
	}
	if (q.query_secdesc.out.sd->dacl->num_aces != 0) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, "DACL has %u aces!\n",
		       q.query_secdesc.out.sd->dacl->num_aces);
		goto done;
	}

	torture_comment(tctx, "try open for read control\n");
	io.ntcreatex.in.access_mask = SEC_STD_READ_CONTROL;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum,
		SEC_STD_READ_CONTROL | SEC_FILE_READ_ATTRIBUTE);
	smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

	torture_comment(tctx, "try open for write => access_denied\n");
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for read => access_denied\n");
	io.ntcreatex.in.access_mask = SEC_FILE_READ_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for generic write => access_denied\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_WRITE;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for generic read => access_denied\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_READ;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "set empty sd\n");
	sd->type &= ~SEC_DESC_DACL_PRESENT;
	sd->dacl = NULL;

	s.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	s.set_secdesc.in.file.fnum = fnum;
	s.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	s.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &s);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "get the sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags =
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Testing the modified DACL */
	if (!(q.query_secdesc.out.sd->type & SEC_DESC_DACL_PRESENT)) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, "DACL_PRESENT flag not set by the server!\n");
		goto done;
	}
	if (q.query_secdesc.out.sd->dacl != NULL) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, "DACL has been created on the server!\n");
		goto done;
	}
done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}

/*
  test the behaviour of the well known SID_CREATOR_OWNER sid, and some generic
  mapping bits
  Test copied to smb2/acls.c for SMB2.
*/
static bool test_creator_sid(struct torture_context *tctx, 
							 struct smbcli_state *cli)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname = BASEDIR "\\creator.txt";
	bool ret = true;
	int fnum = -1;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig, *sd2;
	const char *owner_sid;

	if (!torture_setup_dir(cli, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING SID_CREATOR_OWNER\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC | SEC_STD_WRITE_OWNER;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ | 
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	torture_comment(tctx, "set a sec desc allowing no write by CREATOR_OWNER\n");
	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					SID_CREATOR_OWNER,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
					0,
					NULL);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;

	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "try open for write\n");
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for read\n");
	io.ntcreatex.in.access_mask = SEC_FILE_READ_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for generic write\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_WRITE;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for generic read\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_READ;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "set a sec desc allowing no write by owner\n");
	sd = security_descriptor_dacl_create(tctx,
					0, owner_sid, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
					0,
					NULL);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "check that sd has been mapped correctly\n");
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd);

	torture_comment(tctx, "try open for write\n");
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for read\n");
	io.ntcreatex.in.access_mask = SEC_FILE_READ_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum, 
			   SEC_FILE_READ_DATA|
			   SEC_FILE_READ_ATTRIBUTE);
	smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

	torture_comment(tctx, "try open for generic write\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_WRITE;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for generic read\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_READ;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum, 
			   SEC_RIGHTS_FILE_READ);
	smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

	torture_comment(tctx, "set a sec desc allowing generic read by owner\n");
	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_GENERIC_READ | SEC_STD_ALL,
					0,
					NULL);

	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "check that generic read has been mapped correctly\n");
	sd2 = security_descriptor_dacl_create(tctx,
					 0, owner_sid, NULL,
					 owner_sid,
					 SEC_ACE_TYPE_ACCESS_ALLOWED,
					 SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
					 0,
					 NULL);

	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

	torture_comment(tctx, "try open for write\n");
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for read\n");
	io.ntcreatex.in.access_mask = SEC_FILE_READ_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum, 
			   SEC_FILE_READ_DATA | 
			   SEC_FILE_READ_ATTRIBUTE);
	smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

	torture_comment(tctx, "try open for generic write\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_WRITE;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for generic read\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_READ;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum, SEC_RIGHTS_FILE_READ);
	smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);


	torture_comment(tctx, "put back original sd\n");
	set.set_secdesc.in.sd = sd_orig;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);


done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test the mapping of the SEC_GENERIC_xx bits to SEC_STD_xx and
  SEC_FILE_xx bits
  Test copied to smb2/acls.c for SMB2.
*/
static bool test_generic_bits(struct torture_context *tctx, 
							  struct smbcli_state *cli)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname = BASEDIR "\\generic.txt";
	bool ret = true;
	int fnum = -1, i;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig, *sd2;
	const char *owner_sid;
	const struct {
		uint32_t gen_bits;
		uint32_t specific_bits;
	} file_mappings[] = {
		{ 0,                       0 },
		{ SEC_GENERIC_READ,        SEC_RIGHTS_FILE_READ },
		{ SEC_GENERIC_WRITE,       SEC_RIGHTS_FILE_WRITE },
		{ SEC_GENERIC_EXECUTE,     SEC_RIGHTS_FILE_EXECUTE },
		{ SEC_GENERIC_ALL,         SEC_RIGHTS_FILE_ALL },
		{ SEC_FILE_READ_DATA,      SEC_FILE_READ_DATA },
		{ SEC_FILE_READ_ATTRIBUTE, SEC_FILE_READ_ATTRIBUTE }
	};
	const struct {
		uint32_t gen_bits;
		uint32_t specific_bits;
	} dir_mappings[] = {
		{ 0,                   0 },
		{ SEC_GENERIC_READ,    SEC_RIGHTS_DIR_READ },
		{ SEC_GENERIC_WRITE,   SEC_RIGHTS_DIR_WRITE },
		{ SEC_GENERIC_EXECUTE, SEC_RIGHTS_DIR_EXECUTE },
		{ SEC_GENERIC_ALL,     SEC_RIGHTS_DIR_ALL }
	};
	bool has_restore_privilege;
	bool has_take_ownership_privilege;

	if (!torture_setup_dir(cli, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING FILE GENERIC BITS\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = 
		SEC_STD_READ_CONTROL | 
		SEC_STD_WRITE_DAC | 
		SEC_STD_WRITE_OWNER;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ | 
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	status = torture_check_privilege(cli, 
					    owner_sid, 
					    sec_privilege_name(SEC_PRIV_RESTORE));
	has_restore_privilege = NT_STATUS_IS_OK(status);
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "torture_check_privilege - %s\n",
		    nt_errstr(status));
	}
	torture_comment(tctx, "SEC_PRIV_RESTORE - %s\n", has_restore_privilege?"Yes":"No");

	status = torture_check_privilege(cli, 
					    owner_sid, 
					    sec_privilege_name(SEC_PRIV_TAKE_OWNERSHIP));
	has_take_ownership_privilege = NT_STATUS_IS_OK(status);
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "torture_check_privilege - %s\n",
		    nt_errstr(status));
	}
	torture_comment(tctx, "SEC_PRIV_TAKE_OWNERSHIP - %s\n", has_take_ownership_privilege?"Yes":"No");

	for (i=0;i<ARRAY_SIZE(file_mappings);i++) {
		uint32_t expected_mask = 
			SEC_STD_WRITE_DAC | 
			SEC_STD_READ_CONTROL | 
			SEC_FILE_READ_ATTRIBUTE |
			SEC_STD_DELETE;
		uint32_t expected_mask_anon = SEC_FILE_READ_ATTRIBUTE;

		if (has_restore_privilege) {
			expected_mask_anon |= SEC_STD_DELETE;
		}

		torture_comment(tctx, "Testing generic bits 0x%08x\n",
		       file_mappings[i].gen_bits);
		sd = security_descriptor_dacl_create(tctx,
						0, owner_sid, NULL,
						owner_sid,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						file_mappings[i].gen_bits,
						0,
						NULL);

		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.fnum = fnum;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
		set.set_secdesc.in.sd = sd;

		status = smb_raw_setfileinfo(cli->tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		sd2 = security_descriptor_dacl_create(tctx,
						 0, owner_sid, NULL,
						 owner_sid,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 file_mappings[i].specific_bits,
						 0,
						 NULL);

		status = smb_raw_fileinfo(cli->tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

		io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		status = smb_raw_open(cli->tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum, 
				   expected_mask | file_mappings[i].specific_bits);
		smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

		if (!has_take_ownership_privilege) {
			continue;
		}

		torture_comment(tctx, "Testing generic bits 0x%08x (anonymous)\n",
		       file_mappings[i].gen_bits);
		sd = security_descriptor_dacl_create(tctx,
						0, SID_NT_ANONYMOUS, NULL,
						owner_sid,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						file_mappings[i].gen_bits,
						0,
						NULL);

		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.fnum = fnum;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
		set.set_secdesc.in.sd = sd;

		status = smb_raw_setfileinfo(cli->tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		sd2 = security_descriptor_dacl_create(tctx,
						 0, SID_NT_ANONYMOUS, NULL,
						 owner_sid,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 file_mappings[i].specific_bits,
						 0,
						 NULL);

		status = smb_raw_fileinfo(cli->tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

		io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		status = smb_raw_open(cli->tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum, 
				   expected_mask_anon | file_mappings[i].specific_bits);
		smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);
	}

	torture_comment(tctx, "put back original sd\n");
	set.set_secdesc.in.sd = sd_orig;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);


	torture_comment(tctx, "TESTING DIR GENERIC BITS\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = 
		SEC_STD_READ_CONTROL | 
		SEC_STD_WRITE_DAC | 
		SEC_STD_WRITE_OWNER;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_DIRECTORY;
	io.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ | 
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	status = torture_check_privilege(cli, 
					    owner_sid, 
					    sec_privilege_name(SEC_PRIV_RESTORE));
	has_restore_privilege = NT_STATUS_IS_OK(status);
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "torture_check_privilege - %s\n",
		    nt_errstr(status));
	}
	torture_comment(tctx, "SEC_PRIV_RESTORE - %s\n", has_restore_privilege?"Yes":"No");

	status = torture_check_privilege(cli, 
					    owner_sid, 
					    sec_privilege_name(SEC_PRIV_TAKE_OWNERSHIP));
	has_take_ownership_privilege = NT_STATUS_IS_OK(status);
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "torture_check_privilege - %s\n",
		    nt_errstr(status));
	}
	torture_comment(tctx, "SEC_PRIV_TAKE_OWNERSHIP - %s\n", has_take_ownership_privilege?"Yes":"No");

	for (i=0;i<ARRAY_SIZE(dir_mappings);i++) {
		uint32_t expected_mask = 
			SEC_STD_WRITE_DAC | 
			SEC_STD_READ_CONTROL | 
			SEC_FILE_READ_ATTRIBUTE |
			SEC_STD_DELETE;
		uint32_t expected_mask_anon = SEC_FILE_READ_ATTRIBUTE;

		if (has_restore_privilege) {
			expected_mask_anon |= SEC_STD_DELETE;
		}

		torture_comment(tctx, "Testing generic bits 0x%08x\n",
		       file_mappings[i].gen_bits);
		sd = security_descriptor_dacl_create(tctx,
						0, owner_sid, NULL,
						owner_sid,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						dir_mappings[i].gen_bits,
						0,
						NULL);

		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.fnum = fnum;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
		set.set_secdesc.in.sd = sd;

		status = smb_raw_setfileinfo(cli->tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		sd2 = security_descriptor_dacl_create(tctx,
						 0, owner_sid, NULL,
						 owner_sid,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 dir_mappings[i].specific_bits,
						 0,
						 NULL);

		status = smb_raw_fileinfo(cli->tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

		io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		status = smb_raw_open(cli->tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum, 
				   expected_mask | dir_mappings[i].specific_bits);
		smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

		if (!has_take_ownership_privilege) {
			continue;
		}

		torture_comment(tctx, "Testing generic bits 0x%08x (anonymous)\n",
		       file_mappings[i].gen_bits);
		sd = security_descriptor_dacl_create(tctx,
						0, SID_NT_ANONYMOUS, NULL,
						owner_sid,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						file_mappings[i].gen_bits,
						0,
						NULL);

		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.fnum = fnum;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
		set.set_secdesc.in.sd = sd;

		status = smb_raw_setfileinfo(cli->tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		sd2 = security_descriptor_dacl_create(tctx,
						 0, SID_NT_ANONYMOUS, NULL,
						 owner_sid,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 file_mappings[i].specific_bits,
						 0,
						 NULL);

		status = smb_raw_fileinfo(cli->tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

		io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		status = smb_raw_open(cli->tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum, 
				   expected_mask_anon | dir_mappings[i].specific_bits);
		smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);
	}

	torture_comment(tctx, "put back original sd\n");
	set.set_secdesc.in.sd = sd_orig;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  see what access bits the owner of a file always gets
  Test copied to smb2/acls.c for SMB2.
*/
static bool test_owner_bits(struct torture_context *tctx, 
							struct smbcli_state *cli)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname = BASEDIR "\\test_owner_bits.txt";
	bool ret = true;
	int fnum = -1, i;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig;
	const char *owner_sid;
	bool has_restore_privilege;
	bool has_take_ownership_privilege;
	uint32_t expected_bits;

	if (!torture_setup_dir(cli, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING FILE OWNER BITS\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = 
		SEC_STD_READ_CONTROL | 
		SEC_STD_WRITE_DAC | 
		SEC_STD_WRITE_OWNER;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ | 
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	status = torture_check_privilege(cli, 
					    owner_sid, 
					    sec_privilege_name(SEC_PRIV_RESTORE));
	has_restore_privilege = NT_STATUS_IS_OK(status);
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "torture_check_privilege - %s\n", nt_errstr(status));
	}
	torture_comment(tctx, "SEC_PRIV_RESTORE - %s\n", has_restore_privilege?"Yes":"No");

	status = torture_check_privilege(cli, 
					    owner_sid, 
					    sec_privilege_name(SEC_PRIV_TAKE_OWNERSHIP));
	has_take_ownership_privilege = NT_STATUS_IS_OK(status);
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "torture_check_privilege - %s\n", nt_errstr(status));
	}
	torture_comment(tctx, "SEC_PRIV_TAKE_OWNERSHIP - %s\n", has_take_ownership_privilege?"Yes":"No");

	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_WRITE_DATA,
					0,
					NULL);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;

	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	expected_bits = SEC_FILE_WRITE_DATA | SEC_FILE_READ_ATTRIBUTE;

	for (i=0;i<16;i++) {
		uint32_t bit = (1<<i);
		io.ntcreatex.in.access_mask = bit;
		status = smb_raw_open(cli->tree, tctx, &io);
		if (expected_bits & bit) {
			if (!NT_STATUS_IS_OK(status)) {
				torture_warning(tctx, "failed with access mask 0x%08x of expected 0x%08x\n",
				       bit, expected_bits);
			}
			CHECK_STATUS(status, NT_STATUS_OK);
			CHECK_ACCESS_FLAGS(io.ntcreatex.out.file.fnum, bit | SEC_FILE_READ_ATTRIBUTE);
			smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);
		} else {
			if (NT_STATUS_IS_OK(status)) {
				torture_warning(tctx, "open succeeded with access mask 0x%08x of "
					"expected 0x%08x - should fail\n",
				       bit, expected_bits);
			}
			CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
		}
	}

	torture_comment(tctx, "put back original sd\n");
	set.set_secdesc.in.sd = sd_orig;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}



/*
  test the inheritance of ACL flags onto new files and directories
  Test copied to smb2/acls.c for SMB2.
*/
static bool test_inheritance(struct torture_context *tctx, 
							 struct smbcli_state *cli)
{
	NTSTATUS status;
	union smb_open io;
	const char *dname = BASEDIR "\\inheritance";
	const char *fname1 = BASEDIR "\\inheritance\\testfile";
	const char *fname2 = BASEDIR "\\inheritance\\testdir";
	bool ret = true;
	int fnum=0, fnum2, i;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd2, *sd_orig=NULL, *sd_def1, *sd_def2;
	const char *owner_sid, *group_sid;
	const struct dom_sid *creator_owner;
	const struct {
		uint32_t parent_flags;
		uint32_t file_flags;
		uint32_t dir_flags;
	} test_flags[] = {
		{
			0, 
			0,
			0
		},
		{
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			SEC_ACE_FLAG_OBJECT_INHERIT | 
			SEC_ACE_FLAG_INHERIT_ONLY,
		},
		{
			SEC_ACE_FLAG_CONTAINER_INHERIT,
			0,
			SEC_ACE_FLAG_CONTAINER_INHERIT,
		},
		{
			SEC_ACE_FLAG_OBJECT_INHERIT | 
			SEC_ACE_FLAG_CONTAINER_INHERIT,
			0,
			SEC_ACE_FLAG_OBJECT_INHERIT | 
			SEC_ACE_FLAG_CONTAINER_INHERIT,
		},
		{
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT | 
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT | 
			SEC_ACE_FLAG_CONTAINER_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT | 
			SEC_ACE_FLAG_CONTAINER_INHERIT | 
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY | 
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			SEC_ACE_FLAG_OBJECT_INHERIT | 
			SEC_ACE_FLAG_INHERIT_ONLY,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY | 
			SEC_ACE_FLAG_CONTAINER_INHERIT,
			0,
			SEC_ACE_FLAG_CONTAINER_INHERIT,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY | 
			SEC_ACE_FLAG_CONTAINER_INHERIT | 
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			SEC_ACE_FLAG_CONTAINER_INHERIT | 
			SEC_ACE_FLAG_OBJECT_INHERIT,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY | 
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY | 
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT | 
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY | 
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT | 
			SEC_ACE_FLAG_CONTAINER_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY | 
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT | 
			SEC_ACE_FLAG_CONTAINER_INHERIT | 
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			0,
		}
	};

	if (!torture_setup_dir(cli, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING ACL INHERITANCE\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_DIRECTORY;
	io.ntcreatex.in.share_access = 0;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = dname;

	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER | SECINFO_GROUP;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);
	group_sid = dom_sid_string(tctx, sd_orig->group_sid);

	torture_comment(tctx, "owner_sid is %s\n", owner_sid);
	torture_comment(tctx, "group_sid is %s\n", group_sid);

	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;

	if (torture_setting_bool(tctx, "samba4", false)) {
		/* the default ACL in Samba4 includes the group and
		   other permissions */
		sd_def1 = security_descriptor_dacl_create(tctx,
							 0, owner_sid, NULL,
							 owner_sid,
							 SEC_ACE_TYPE_ACCESS_ALLOWED,
							 SEC_RIGHTS_FILE_ALL,
							 0,
							 group_sid,
							 SEC_ACE_TYPE_ACCESS_ALLOWED,
							 SEC_RIGHTS_FILE_READ | SEC_FILE_EXECUTE,
							 0,
							 SID_WORLD,
							 SEC_ACE_TYPE_ACCESS_ALLOWED,
							 SEC_RIGHTS_FILE_READ | SEC_FILE_EXECUTE,
							 0,
							 SID_NT_SYSTEM,
							 SEC_ACE_TYPE_ACCESS_ALLOWED,
							 SEC_RIGHTS_FILE_ALL,
							 0,
							 NULL);
	} else {
		/*
		 * The Windows Default ACL for a new file, when there is no ACL to be
		 * inherited: FullControl for the owner and SYSTEM.
		 */
		sd_def1 = security_descriptor_dacl_create(tctx,
							 0, owner_sid, NULL,
							 owner_sid,
							 SEC_ACE_TYPE_ACCESS_ALLOWED,
							 SEC_RIGHTS_FILE_ALL,
							 0,
							 SID_NT_SYSTEM,
							 SEC_ACE_TYPE_ACCESS_ALLOWED,
							 SEC_RIGHTS_FILE_ALL,
							 0,
							 NULL);
	}

	/*
	 * Use this in the case the system being tested does not add an ACE for
	 * the SYSTEM SID.
	 */
	sd_def2 = security_descriptor_dacl_create(tctx,
					    0, owner_sid, NULL,
					    owner_sid,
					    SEC_ACE_TYPE_ACCESS_ALLOWED,
					    SEC_RIGHTS_FILE_ALL,
					    0,
					    NULL);

	creator_owner = dom_sid_parse_talloc(tctx, SID_CREATOR_OWNER);

	for (i=0;i<ARRAY_SIZE(test_flags);i++) {
		sd = security_descriptor_dacl_create(tctx,
						0, NULL, NULL,
						SID_CREATOR_OWNER,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_FILE_WRITE_DATA,
						test_flags[i].parent_flags,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_FILE_ALL | SEC_STD_ALL,
						0,
						NULL);
		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.fnum = fnum;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
		set.set_secdesc.in.sd = sd;
		status = smb_raw_setfileinfo(cli->tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		io.ntcreatex.in.fname = fname1;
		io.ntcreatex.in.create_options = 0;
		status = smb_raw_open(cli->tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		fnum2 = io.ntcreatex.out.file.fnum;

		q.query_secdesc.in.file.fnum = fnum2;
		status = smb_raw_fileinfo(cli->tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);

		smbcli_close(cli->tree, fnum2);
		smbcli_unlink(cli->tree, fname1);

		if (!(test_flags[i].parent_flags & SEC_ACE_FLAG_OBJECT_INHERIT)) {
			if (!security_descriptor_equal(q.query_secdesc.out.sd, sd_def1) &&
			    !security_descriptor_equal(q.query_secdesc.out.sd, sd_def2)) {
				torture_warning(tctx, "Expected default sd "
				    "for i=%d:\n", i);
				NDR_PRINT_DEBUG(security_descriptor, sd_def1);
				torture_warning(tctx, "at %d - got:\n", i);
				NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
			}
			goto check_dir;
		}

		if (q.query_secdesc.out.sd->dacl == NULL ||
		    q.query_secdesc.out.sd->dacl->num_aces != 1 ||
		    q.query_secdesc.out.sd->dacl->aces[0].access_mask != SEC_FILE_WRITE_DATA ||
		    !dom_sid_equal(&q.query_secdesc.out.sd->dacl->aces[0].trustee,
				   sd_orig->owner_sid)) {
			ret = false;
			torture_warning(tctx, "Bad sd in child file at %d\n", i);
			NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
			goto check_dir;
		}

		if (q.query_secdesc.out.sd->dacl->aces[0].flags != 
		    test_flags[i].file_flags) {
			torture_warning(tctx, "incorrect file_flags 0x%x - expected 0x%x for parent 0x%x with (i=%d)\n",
			       q.query_secdesc.out.sd->dacl->aces[0].flags,
			       test_flags[i].file_flags,
			       test_flags[i].parent_flags,
			       i);
			ret = false;
		}

	check_dir:
		io.ntcreatex.in.fname = fname2;
		io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
		status = smb_raw_open(cli->tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		fnum2 = io.ntcreatex.out.file.fnum;

		q.query_secdesc.in.file.fnum = fnum2;
		status = smb_raw_fileinfo(cli->tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);

		smbcli_close(cli->tree, fnum2);
		smbcli_rmdir(cli->tree, fname2);

		if (!(test_flags[i].parent_flags & SEC_ACE_FLAG_CONTAINER_INHERIT) &&
		    (!(test_flags[i].parent_flags & SEC_ACE_FLAG_OBJECT_INHERIT) ||
		     (test_flags[i].parent_flags & SEC_ACE_FLAG_NO_PROPAGATE_INHERIT))) {
			if (!security_descriptor_equal(q.query_secdesc.out.sd, sd_def1) &&
			    !security_descriptor_equal(q.query_secdesc.out.sd, sd_def2)) {
				torture_warning(tctx, "Expected default sd for dir at %d:\n", i);
				NDR_PRINT_DEBUG(security_descriptor, sd_def1);
				torture_warning(tctx, "got:\n");
				NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
			}
			continue;
		}

		if ((test_flags[i].parent_flags & SEC_ACE_FLAG_CONTAINER_INHERIT) && 
		    (test_flags[i].parent_flags & SEC_ACE_FLAG_NO_PROPAGATE_INHERIT)) {
			if (q.query_secdesc.out.sd->dacl == NULL ||
			    q.query_secdesc.out.sd->dacl->num_aces != 1 ||
			    q.query_secdesc.out.sd->dacl->aces[0].access_mask != SEC_FILE_WRITE_DATA ||
			    !dom_sid_equal(&q.query_secdesc.out.sd->dacl->aces[0].trustee,
					   sd_orig->owner_sid) ||
			    q.query_secdesc.out.sd->dacl->aces[0].flags != test_flags[i].dir_flags) {
				torture_warning(tctx, "(CI & NP) Bad sd in child dir - expected 0x%x for parent 0x%x (i=%d)\n",
				       test_flags[i].dir_flags,
				       test_flags[i].parent_flags, i);
				NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
				torture_comment(tctx, "FYI, here is the parent sd:\n");
				NDR_PRINT_DEBUG(security_descriptor, sd);
				ret = false;
				continue;
			}
		} else if (test_flags[i].parent_flags & SEC_ACE_FLAG_CONTAINER_INHERIT) {
			if (q.query_secdesc.out.sd->dacl == NULL ||
			    q.query_secdesc.out.sd->dacl->num_aces != 2 ||
			    q.query_secdesc.out.sd->dacl->aces[0].access_mask != SEC_FILE_WRITE_DATA ||
			    !dom_sid_equal(&q.query_secdesc.out.sd->dacl->aces[0].trustee,
					   sd_orig->owner_sid) ||
			    q.query_secdesc.out.sd->dacl->aces[1].access_mask != SEC_FILE_WRITE_DATA ||
			    !dom_sid_equal(&q.query_secdesc.out.sd->dacl->aces[1].trustee,
					   creator_owner) ||
			    q.query_secdesc.out.sd->dacl->aces[0].flags != 0 ||
			    q.query_secdesc.out.sd->dacl->aces[1].flags != 
			    (test_flags[i].dir_flags | SEC_ACE_FLAG_INHERIT_ONLY)) {
				torture_warning(tctx, "(CI) Bad sd in child dir - expected 0x%x for parent 0x%x (i=%d)\n",
				       test_flags[i].dir_flags,
				       test_flags[i].parent_flags, i);
				NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
				torture_comment(tctx, "FYI, here is the parent sd:\n");
				NDR_PRINT_DEBUG(security_descriptor, sd);
				ret = false;
				continue;
			}
		} else {
			if (q.query_secdesc.out.sd->dacl == NULL ||
			    q.query_secdesc.out.sd->dacl->num_aces != 1 ||
			    q.query_secdesc.out.sd->dacl->aces[0].access_mask != SEC_FILE_WRITE_DATA ||
			    !dom_sid_equal(&q.query_secdesc.out.sd->dacl->aces[0].trustee,
					   creator_owner) ||
			    q.query_secdesc.out.sd->dacl->aces[0].flags != test_flags[i].dir_flags) {
				torture_warning(tctx, "(0) Bad sd in child dir - expected 0x%x for parent 0x%x (i=%d)\n",
				       test_flags[i].dir_flags,
				       test_flags[i].parent_flags, i);
				NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
				torture_comment(tctx, "FYI, here is the parent sd:\n");
				NDR_PRINT_DEBUG(security_descriptor, sd);
				ret = false;
				continue;
			}
		}
	}

	torture_comment(tctx, "Testing access checks on inherited create with %s\n", fname1);
	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_WRITE_DATA | SEC_STD_WRITE_DAC,
					SEC_ACE_FLAG_OBJECT_INHERIT,
					SID_WORLD,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_ALL | SEC_STD_ALL,
					0,
					NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Check DACL we just set. */
	torture_comment(tctx, "checking new sd\n");
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd);

	io.ntcreatex.in.fname = fname1;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	CHECK_ACCESS_FLAGS(fnum2, SEC_RIGHTS_FILE_ALL);

	q.query_secdesc.in.file.fnum = fnum2;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	smbcli_close(cli->tree, fnum2);

	sd2 = security_descriptor_dacl_create(tctx,
					 0, owner_sid, NULL,
					 owner_sid,
					 SEC_ACE_TYPE_ACCESS_ALLOWED,
					 SEC_FILE_WRITE_DATA | SEC_STD_WRITE_DAC,
					 0,
					 NULL);
	CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	status = smb_raw_open(cli->tree, tctx, &io);
	if (NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "failed: w2k3 ACL bug (allowed open when ACL should deny)\n");
		ret = false;
		fnum2 = io.ntcreatex.out.file.fnum;
		CHECK_ACCESS_FLAGS(fnum2, SEC_RIGHTS_FILE_ALL);
		smbcli_close(cli->tree, fnum2);
	} else {
		if (TARGET_IS_WIN7(tctx)) {
			CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
		} else {
			CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
		}
	}

	torture_comment(tctx, "trying without execute\n");
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL & ~SEC_FILE_EXECUTE;
	status = smb_raw_open(cli->tree, tctx, &io);
	if (TARGET_IS_WIN7(tctx)) {
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
	}

	torture_comment(tctx, "and with full permissions again\n");
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	status = smb_raw_open(cli->tree, tctx, &io);
	if (TARGET_IS_WIN7(tctx)) {
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
	}

	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	CHECK_ACCESS_FLAGS(fnum2, SEC_FILE_WRITE_DATA | SEC_FILE_READ_ATTRIBUTE);
	smbcli_close(cli->tree, fnum2);

	torture_comment(tctx, "put back original sd\n");
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd_orig;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	smbcli_close(cli->tree, fnum);

	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	status = smb_raw_open(cli->tree, tctx, &io);
	if (TARGET_IS_WIN7(tctx)) {
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
	}

	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	CHECK_ACCESS_FLAGS(fnum2, SEC_FILE_WRITE_DATA | SEC_FILE_READ_ATTRIBUTE);
	smbcli_close(cli->tree, fnum2);

done:
	if (sd_orig != NULL) {
		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.fnum = fnum;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
		set.set_secdesc.in.sd = sd_orig;
		status = smb_raw_setfileinfo(cli->tree, &set);
	}

	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname1);
	smbcli_rmdir(cli->tree, dname);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	if (!ret) {
		torture_result(tctx,
			TORTURE_FAIL, "(%s) test_inheritance\n",
			__location__);
	}

	return ret;
}

static bool test_inheritance_flags(struct torture_context *tctx,
    struct smbcli_state *cli)
{
	NTSTATUS status;
	union smb_open io;
	const char *dname = BASEDIR "\\inheritance";
	const char *fname1 = BASEDIR "\\inheritance\\testfile";
	bool ret = true;
	int fnum=0, fnum2, i, j;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd2, *sd_orig=NULL;
	const char *owner_sid;
	struct {
		uint32_t parent_set_sd_type; /* 3 options */
		uint32_t parent_set_ace_inherit; /* 1 option */
		uint32_t parent_get_sd_type;
		uint32_t parent_get_ace_inherit;
		uint32_t child_get_sd_type;
		uint32_t child_get_ace_inherit;
	} tflags[16] = {{0}}; /* 2^4 */

	for (i = 0; i < 15; i++) {
		torture_comment(tctx, "i=%d:", i);

		ZERO_STRUCT(tflags[i]);

		if (i & 1) {
			tflags[i].parent_set_sd_type |=
			    SEC_DESC_DACL_AUTO_INHERITED;
			torture_comment(tctx, "AUTO_INHERITED, ");
		}
		if (i & 2) {
			tflags[i].parent_set_sd_type |=
			    SEC_DESC_DACL_AUTO_INHERIT_REQ;
			torture_comment(tctx, "AUTO_INHERIT_REQ, ");
		}
		if (i & 4) {
			tflags[i].parent_set_sd_type |=
			    SEC_DESC_DACL_PROTECTED;
			tflags[i].parent_get_sd_type |=
			    SEC_DESC_DACL_PROTECTED;
			torture_comment(tctx, "PROTECTED, ");
		}
		if (i & 8) {
			tflags[i].parent_set_ace_inherit |=
			    SEC_ACE_FLAG_INHERITED_ACE;
			tflags[i].parent_get_ace_inherit |=
			    SEC_ACE_FLAG_INHERITED_ACE;
			torture_comment(tctx, "INHERITED, ");
		}

		if ((tflags[i].parent_set_sd_type &
		    (SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_DACL_AUTO_INHERIT_REQ)) ==
		    (SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_DACL_AUTO_INHERIT_REQ)) {
			tflags[i].parent_get_sd_type |=
			    SEC_DESC_DACL_AUTO_INHERITED;
			tflags[i].child_get_sd_type |=
			    SEC_DESC_DACL_AUTO_INHERITED;
			tflags[i].child_get_ace_inherit |=
			    SEC_ACE_FLAG_INHERITED_ACE;
			torture_comment(tctx, "  ... parent is AUTO INHERITED");
		}

		if (tflags[i].parent_set_ace_inherit &
		    SEC_ACE_FLAG_INHERITED_ACE) {
			tflags[i].parent_get_ace_inherit =
			    SEC_ACE_FLAG_INHERITED_ACE;
			torture_comment(tctx, "  ... parent ACE is INHERITED");
		}

		torture_comment(tctx, "\n");
	}

	if (!torture_setup_dir(cli, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING ACL INHERITANCE FLAGS\n");

	ZERO_STRUCT(io);

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_DIRECTORY;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = dname;

	torture_comment(tctx, "creating initial directory %s\n", dname);
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "getting original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);
	torture_comment(tctx, "owner_sid is %s\n", owner_sid);

	for (i=0; i < ARRAY_SIZE(tflags); i++) {
		torture_comment(tctx, "setting a new sd on directory, pass #%d\n", i);

		sd = security_descriptor_dacl_create(tctx,
						tflags[i].parent_set_sd_type,
						NULL, NULL,
						owner_sid,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_FILE_WRITE_DATA | SEC_STD_WRITE_DAC,
						SEC_ACE_FLAG_OBJECT_INHERIT |
						SEC_ACE_FLAG_CONTAINER_INHERIT |
						tflags[i].parent_set_ace_inherit,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_FILE_ALL | SEC_STD_ALL,
						0,
						NULL);
		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.fnum = fnum;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
		set.set_secdesc.in.sd = sd;
		status = smb_raw_setfileinfo(cli->tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		/*
		 * Check DACL we just set, except change the bits to what they
		 * should be.
		 */
		torture_comment(tctx, "  checking new sd\n");

		/* REQ bit should always be false. */
		sd->type &= ~SEC_DESC_DACL_AUTO_INHERIT_REQ;

		if ((tflags[i].parent_get_sd_type & SEC_DESC_DACL_AUTO_INHERITED) == 0)
			sd->type &= ~SEC_DESC_DACL_AUTO_INHERITED;

		q.query_secdesc.in.file.fnum = fnum;
		q.query_secdesc.in.secinfo_flags = SECINFO_DACL;
		status = smb_raw_fileinfo(cli->tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd);

		/* Create file. */
		torture_comment(tctx, "  creating file %s\n", fname1);
		io.ntcreatex.in.fname = fname1;
		io.ntcreatex.in.create_options = 0;
		io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
		io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
		io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
		status = smb_raw_open(cli->tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		fnum2 = io.ntcreatex.out.file.fnum;
		CHECK_ACCESS_FLAGS(fnum2, SEC_RIGHTS_FILE_ALL);

		q.query_secdesc.in.file.fnum = fnum2;
		q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
		status = smb_raw_fileinfo(cli->tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);

		torture_comment(tctx, "  checking sd on file %s\n", fname1);
		sd2 = security_descriptor_dacl_create(tctx,
						 tflags[i].child_get_sd_type,
						 owner_sid, NULL,
						 owner_sid,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 SEC_FILE_WRITE_DATA | SEC_STD_WRITE_DAC,
						 tflags[i].child_get_ace_inherit,
						 NULL);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

		/*
		 * Set new sd on file ... prove that the bits have nothing to
		 * do with the parents bits when manually setting an ACL. The
		 * _AUTO_INHERITED bit comes directly from the ACL set.
		 */
		for (j = 0; j < ARRAY_SIZE(tflags); j++) {
			torture_comment(tctx, "  setting new file sd, pass #%d\n", j);

			/* Change sd type. */
			sd2->type &= ~(SEC_DESC_DACL_AUTO_INHERITED |
			    SEC_DESC_DACL_AUTO_INHERIT_REQ |
			    SEC_DESC_DACL_PROTECTED);
			sd2->type |= tflags[j].parent_set_sd_type;

			sd2->dacl->aces[0].flags &=
			    ~SEC_ACE_FLAG_INHERITED_ACE;
			sd2->dacl->aces[0].flags |=
			    tflags[j].parent_set_ace_inherit;

			set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
			set.set_secdesc.in.file.fnum = fnum2;
			set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
			set.set_secdesc.in.sd = sd2;
			status = smb_raw_setfileinfo(cli->tree, &set);
			CHECK_STATUS(status, NT_STATUS_OK);

			/* Check DACL we just set. */
			sd2->type &= ~SEC_DESC_DACL_AUTO_INHERIT_REQ;
			if ((tflags[j].parent_get_sd_type & SEC_DESC_DACL_AUTO_INHERITED) == 0)
				sd2->type &= ~SEC_DESC_DACL_AUTO_INHERITED;

			q.query_secdesc.in.file.fnum = fnum2;
			q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
			status = smb_raw_fileinfo(cli->tree, tctx, &q);
			CHECK_STATUS(status, NT_STATUS_OK);

			CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);
		}

		smbcli_close(cli->tree, fnum2);
		smbcli_unlink(cli->tree, fname1);
	}

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	if (!ret) {
		torture_result(tctx,
			TORTURE_FAIL, "(%s) test_inheritance_flags\n",
			__location__);
	}

	return ret;
}

/*
  test dynamic acl inheritance
  Test copied to smb2/acls.c for SMB2.
*/
static bool test_inheritance_dynamic(struct torture_context *tctx, 
									 struct smbcli_state *cli)
{
	NTSTATUS status;
	union smb_open io;
	const char *dname = BASEDIR "\\inheritance2";
	const char *fname1 = BASEDIR "\\inheritance2\\testfile";
	bool ret = true;
	int fnum=0, fnum2;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig=NULL;
	const char *owner_sid;
	
	torture_comment(tctx, "TESTING DYNAMIC ACL INHERITANCE\n");

	if (!torture_setup_dir(cli, BASEDIR))
		return false;

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_DIRECTORY;
	io.ntcreatex.in.share_access = 0;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = dname;

	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	torture_comment(tctx, "owner_sid is %s\n", owner_sid);

	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_WRITE_DATA | SEC_STD_DELETE | SEC_FILE_READ_ATTRIBUTE,
					SEC_ACE_FLAG_OBJECT_INHERIT,
					NULL);
	sd->type |= SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_DACL_AUTO_INHERIT_REQ;

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "create a file with an inherited acl\n");
	io.ntcreatex.in.fname = fname1;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_READ_ATTRIBUTE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	smbcli_close(cli->tree, fnum2);

	torture_comment(tctx, "try and access file with base rights - should be OK\n");
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	smbcli_close(cli->tree, fnum2);

	torture_comment(tctx, "try and access file with extra rights - should be denied\n");
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA | SEC_FILE_EXECUTE;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "update parent sd\n");
	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_WRITE_DATA | SEC_STD_DELETE | SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE,
					SEC_ACE_FLAG_OBJECT_INHERIT,
					NULL);
	sd->type |= SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_DACL_AUTO_INHERIT_REQ;

	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "try and access file with base rights - should be OK\n");
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	smbcli_close(cli->tree, fnum2);


	torture_comment(tctx, "try and access now - should be OK if dynamic inheritance works\n");
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA | SEC_FILE_EXECUTE;
	status = smb_raw_open(cli->tree, tctx, &io);
	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		torture_comment(tctx, "Server does not have dynamic inheritance\n");
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		torture_comment(tctx, "Server does have dynamic inheritance\n");
	}
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	smbcli_unlink(cli->tree, fname1);

done:
	if (sd_orig != NULL) {
		torture_comment(tctx, "put back original sd\n");
		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.fnum = fnum;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
		set.set_secdesc.in.sd = sd_orig;
		status = smb_raw_setfileinfo(cli->tree, &set);
	}
	smbcli_close(cli->tree, fnum);
	smbcli_rmdir(cli->tree, dname);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

#define CHECK_STATUS_FOR_BIT_ACTION(status, bits, action) do { \
	if (!(bits & desired_64)) {\
		CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED); \
		action; \
	} else { \
		CHECK_STATUS(status, NT_STATUS_OK); \
	} \
} while (0)

#define CHECK_STATUS_FOR_BIT(status, bits, access) do { \
	if (NT_STATUS_IS_OK(status)) { \
		if (!(granted & access)) {\
			ret = false; \
			torture_result(tctx, TORTURE_FAIL, "(%s) %s but flags 0x%08X are not granted! granted[0x%08X] desired[0x%08X]\n", \
			       __location__, nt_errstr(status), access, granted, desired); \
			goto done; \
		} \
	} else { \
		if (granted & access) {\
			ret = false; \
			torture_result(tctx, TORTURE_FAIL, "(%s) %s but flags 0x%08X are granted! granted[0x%08X] desired[0x%08X]\n", \
			       __location__, nt_errstr(status), access, granted, desired); \
			goto done; \
		} \
	} \
	CHECK_STATUS_FOR_BIT_ACTION(status, bits, do {} while (0)); \
} while (0)

#if 0

/* test what access mask is needed for getting and setting security_descriptors
  Test copied to smb2/acls.c for SMB2. */
static bool test_sd_get_set(struct torture_context *tctx, 
							struct smbcli_state *cli)
{
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_fileinfo fi;
	union smb_setfileinfo si;
	struct security_descriptor *sd;
	struct security_descriptor *sd_owner = NULL;
	struct security_descriptor *sd_group = NULL;
	struct security_descriptor *sd_dacl = NULL;
	struct security_descriptor *sd_sacl = NULL;
	int fnum=0;
	const char *fname = BASEDIR "\\sd_get_set.txt";
	uint64_t desired_64;
	uint32_t desired = 0, granted;
	int i = 0;
#define NO_BITS_HACK (((uint64_t)1)<<32)
	uint64_t open_bits =
		SEC_MASK_GENERIC |
		SEC_FLAG_SYSTEM_SECURITY |
		SEC_FLAG_MAXIMUM_ALLOWED |
		SEC_STD_ALL |
		SEC_FILE_ALL | 
		NO_BITS_HACK;
	uint64_t get_owner_bits = SEC_MASK_GENERIC | SEC_FLAG_MAXIMUM_ALLOWED | SEC_STD_READ_CONTROL;
	uint64_t set_owner_bits = SEC_GENERIC_ALL  | SEC_FLAG_MAXIMUM_ALLOWED | SEC_STD_WRITE_OWNER;
	uint64_t get_group_bits = SEC_MASK_GENERIC | SEC_FLAG_MAXIMUM_ALLOWED | SEC_STD_READ_CONTROL;
	uint64_t set_group_bits = SEC_GENERIC_ALL  | SEC_FLAG_MAXIMUM_ALLOWED | SEC_STD_WRITE_OWNER;
	uint64_t get_dacl_bits  = SEC_MASK_GENERIC | SEC_FLAG_MAXIMUM_ALLOWED | SEC_STD_READ_CONTROL;
	uint64_t set_dacl_bits  = SEC_GENERIC_ALL  | SEC_FLAG_MAXIMUM_ALLOWED | SEC_STD_WRITE_DAC;
	uint64_t get_sacl_bits  = SEC_FLAG_SYSTEM_SECURITY;
	uint64_t set_sacl_bits  = SEC_FLAG_SYSTEM_SECURITY;

	if (!torture_setup_dir(cli, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING ACCESS MASKS FOR SD GET/SET\n");

	/* first create a file with full access for everyone */
	sd = security_descriptor_dacl_create(tctx,
					0, SID_NT_ANONYMOUS, SID_BUILTIN_USERS,
					SID_WORLD,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_GENERIC_ALL,
					0,
					NULL);
	sd->type |= SEC_DESC_SACL_PRESENT;
	sd->sacl = NULL;
	io.ntcreatex.level = RAW_OPEN_NTTRANS_CREATE;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_GENERIC_ALL;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	io.ntcreatex.in.sec_desc = sd;
	io.ntcreatex.in.ea_list = NULL;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	status = smbcli_close(cli->tree, fnum);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* 
	 * now try each access_mask bit and no bit at all in a loop
	 * and see what's allowed
	 * NOTE: if i == 32 it means access_mask = 0 (see NO_BITS_HACK above)
	 */
	for (i=0; i <= 32; i++) {
		desired_64 = ((uint64_t)1) << i;
		desired = (uint32_t)desired_64;

		/* first open the file with the desired access */
		io.ntcreatex.level = RAW_OPEN_NTCREATEX;
		io.ntcreatex.in.access_mask = desired;
		io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
		status = smb_raw_open(cli->tree, tctx, &io);
		CHECK_STATUS_FOR_BIT_ACTION(status, open_bits, goto next);
		fnum = io.ntcreatex.out.file.fnum;

		/* then check what access was granted */
		fi.access_information.level		= RAW_FILEINFO_ACCESS_INFORMATION;
		fi.access_information.in.file.fnum	= fnum;
		status = smb_raw_fileinfo(cli->tree, tctx, &fi);
		CHECK_STATUS(status, NT_STATUS_OK);
		granted = fi.access_information.out.access_flags;

		/* test the owner */
		ZERO_STRUCT(fi);
		fi.query_secdesc.level			= RAW_FILEINFO_SEC_DESC;
		fi.query_secdesc.in.file.fnum		= fnum;
		fi.query_secdesc.in.secinfo_flags	= SECINFO_OWNER;
		status = smb_raw_fileinfo(cli->tree, tctx, &fi);
		CHECK_STATUS_FOR_BIT(status, get_owner_bits, SEC_STD_READ_CONTROL);
		if (fi.query_secdesc.out.sd) {
			sd_owner = fi.query_secdesc.out.sd;
		} else if (!sd_owner) {
			sd_owner = sd;
		}
		si.set_secdesc.level			= RAW_SFILEINFO_SEC_DESC;
		si.set_secdesc.in.file.fnum		= fnum;
		si.set_secdesc.in.secinfo_flags		= SECINFO_OWNER;
		si.set_secdesc.in.sd			= sd_owner;
		status = smb_raw_setfileinfo(cli->tree, &si);
		CHECK_STATUS_FOR_BIT(status, set_owner_bits, SEC_STD_WRITE_OWNER);

		/* test the group */
		ZERO_STRUCT(fi);
		fi.query_secdesc.level			= RAW_FILEINFO_SEC_DESC;
		fi.query_secdesc.in.file.fnum		= fnum;
		fi.query_secdesc.in.secinfo_flags	= SECINFO_GROUP;
		status = smb_raw_fileinfo(cli->tree, tctx, &fi);
		CHECK_STATUS_FOR_BIT(status, get_group_bits, SEC_STD_READ_CONTROL);
		if (fi.query_secdesc.out.sd) {
			sd_group = fi.query_secdesc.out.sd;
		} else if (!sd_group) {
			sd_group = sd;
		}
		si.set_secdesc.level			= RAW_SFILEINFO_SEC_DESC;
		si.set_secdesc.in.file.fnum		= fnum;
		si.set_secdesc.in.secinfo_flags		= SECINFO_GROUP;
		si.set_secdesc.in.sd			= sd_group;
		status = smb_raw_setfileinfo(cli->tree, &si);
		CHECK_STATUS_FOR_BIT(status, set_group_bits, SEC_STD_WRITE_OWNER);

		/* test the DACL */
		ZERO_STRUCT(fi);
		fi.query_secdesc.level			= RAW_FILEINFO_SEC_DESC;
		fi.query_secdesc.in.file.fnum		= fnum;
		fi.query_secdesc.in.secinfo_flags	= SECINFO_DACL;
		status = smb_raw_fileinfo(cli->tree, tctx, &fi);
		CHECK_STATUS_FOR_BIT(status, get_dacl_bits, SEC_STD_READ_CONTROL);
		if (fi.query_secdesc.out.sd) {
			sd_dacl = fi.query_secdesc.out.sd;
		} else if (!sd_dacl) {
			sd_dacl = sd;
		}
		si.set_secdesc.level			= RAW_SFILEINFO_SEC_DESC;
		si.set_secdesc.in.file.fnum		= fnum;
		si.set_secdesc.in.secinfo_flags		= SECINFO_DACL;
		si.set_secdesc.in.sd			= sd_dacl;
		status = smb_raw_setfileinfo(cli->tree, &si);
		CHECK_STATUS_FOR_BIT(status, set_dacl_bits, SEC_STD_WRITE_DAC);

		/* test the SACL */
		ZERO_STRUCT(fi);
		fi.query_secdesc.level			= RAW_FILEINFO_SEC_DESC;
		fi.query_secdesc.in.file.fnum		= fnum;
		fi.query_secdesc.in.secinfo_flags	= SECINFO_SACL;
		status = smb_raw_fileinfo(cli->tree, tctx, &fi);
		CHECK_STATUS_FOR_BIT(status, get_sacl_bits, SEC_FLAG_SYSTEM_SECURITY);
		if (fi.query_secdesc.out.sd) {
			sd_sacl = fi.query_secdesc.out.sd;
		} else if (!sd_sacl) {
			sd_sacl = sd;
		}
		si.set_secdesc.level			= RAW_SFILEINFO_SEC_DESC;
		si.set_secdesc.in.file.fnum		= fnum;
		si.set_secdesc.in.secinfo_flags		= SECINFO_SACL;
		si.set_secdesc.in.sd			= sd_sacl;
		status = smb_raw_setfileinfo(cli->tree, &si);
		CHECK_STATUS_FOR_BIT(status, set_sacl_bits, SEC_FLAG_SYSTEM_SECURITY);

		/* close the handle */
		status = smbcli_close(cli->tree, fnum);
		CHECK_STATUS(status, NT_STATUS_OK);
next:
		continue;
	}

done:
	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

#endif


#if 1 // Enable testing of NTACL interaction with fuse backend.
/*
 * The attributes cache for each FUSE mount point is 2 seconds.
 * The test accesses from two different mount points so we need to
 * allow the attr cache to timeout to get the updated attributes.
 */
#define WAIT_ATTR_CACHE_TIMEOUT    sleep(5)

#define SET_OWNER_FNAME		"fuse_test.txt"
#define SET_OWNER_DNAME		"fuse_test_dir"
#define DEF_ACL_FNAME		"def_acl.txt"
#define DEF_ACL_DNAME		"def_acl_dir"
#define SETGID_DNAME		"setgid_dir"
#define SETGID_FNAME		"setgid_file"
#define MAX_DIR_LEVELS		3

#define LDAP_SEARCH_USER	"(&(objectClass=user)(sAMAccountName=%s))"
#define LDAP_SEARCH_GROUP	"(&(objectClass=group)(sAMAccountName=%s))"

static char* get_ldap_sid_str(struct torture_context *tctx, char *searchstr)
{
	ADS_STRUCT *ads = NULL;
	ADS_STATUS ads_status;
	const char *attrs[] = {"objectSid", NULL};
	LDAPMessage *ads_res = NULL;
	char *realm = NULL ;
	char *wkg = NULL;
	char *hst = NULL;
	char *adm_usr = NULL;
	char *adm_pwd = NULL;
	char *sid_str = NULL;

	realm	= torture_setting_string(tctx, ACL_ADS_RLM, strdup("REPUBLIC.WINDC"));
	wkg	= torture_setting_string(tctx, ACL_ADS_WKG, strdup("REPUBLIC"));
	hst	= torture_setting_string(tctx, ACL_ADS_HST, strdup("WIN-17736MH9H4F.republic.windc"));
	adm_usr = torture_setting_string(tctx, ACL_ADM_USR, strdup("Administrator"));
	adm_pwd = torture_setting_string(tctx, ACL_ADM_PWD, strdup("Admin123"));

	ads = ads_init(realm, wkg, hst);
	if (!ads) {
		torture_comment("ads_init failed. realm[%s] wkg[%s] hst[%s] Error [%d] %s\n",
			realm, wkg, hst, errno, strerror(errno));
		goto exit;
	}

	ads->auth.flags |= 0; // possiblty ADS_AUTH_NO_BIND
	ads->auth.user_name = adm_usr;
	ads->auth.password = adm_pwd;

	ads_status = ads_connect(ads);
	if (!ADS_ERR_OK(ads_status)) {
		torture_comment(tctx, "ads_connect failed. status 0x%x\n", ads_status);
		goto exit;
	}

	ads_status = ads_do_search_retry(ads, ads->config.bind_path, LDAP_SCOPE_SUBTREE,
						searchstr, attrs, &ads_res);
	if (!ADS_ERR_OK(ads_status)) {
		torture_comment(tctx, "ads_do_search_retry failed. searchstr [%s] status 0x%x\n",
					searchstr, ads_status);
		goto exit;
	}

	sid_str = ads_get_sid_from_results(ads, ads_res);

exit:
	if (ads_res)
		ads_msgfree(ads, ads_res);
	if (ads)
		ads_destroy(&ads);

	return sid_str;
}

static char* get_user_sid_str(struct torture_context *tctx, char *username)
{
	char searchstr[512];

	if (strchr(username, '\\') || strchr(username, '/') || strchr(username, '%')) {
		torture_comment(tctx, "username [%s] cannot contain Domain name or password\n", username);
		return NULL;
	}

	snprintf(searchstr, 512, LDAP_SEARCH_USER, username);
	return get_ldap_sid_str(tctx, searchstr);
}

static char* get_group_sid_str(struct torture_context *tctx, char *group)
{
	char searchstr[512];

	if (strchr(group, '\\') || strchr(group, '/') || strchr(group, '%')) {
		torture_comment(tctx, "group name [%s] cannot contain Domain name or password\n", group);
		return NULL;
	}

	snprintf(searchstr, 512, LDAP_SEARCH_GROUP, group);
	return get_ldap_sid_str(tctx, searchstr);
}

static bool get_stat_info(struct torture_context *tctx, char *path, struct stat *sbuf)
{
	int rc;
	bool ret;

	rc = stat(path, sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get stat for [%s]. rc[%d] errno [%d]\n",
					path, rc, errno);
		ret = false;
		goto done;
	}
	ret = true;
done:

	return ret;
}

static bool verify_perm(struct torture_context *tctx, struct stat *a, struct stat *b)
{
	mode_t amode, bmode;

	//printf(" mode[a:%o | b:%o] st_uid [a:%u | b:%u] st_gid [a:%u | b:%u]\n",
	//	a->st_mode, b->st_mode, a->st_uid, b->st_uid, a->st_gid, b->st_gid);
	amode = (a->st_mode & (S_IRWXU | S_IRWXG | S_IRWXO));
	bmode = (b->st_mode & (S_IRWXU | S_IRWXG | S_IRWXO));
	if (amode != bmode) {
		torture_comment(tctx, "mode does not match a->st_mode[%o], b->st_mode[%o]\n",
					amode, bmode);
		return false;
	}
	if (a->st_uid != b->st_uid) {
		torture_comment(tctx, "owner does not match a->st_uid [%u] b->st_uid [%u]\n",
					a->st_uid, b->st_uid);
		return false;
	}
	if (a->st_gid != b->st_gid) {
		torture_comment(tctx, "owning group does not match a->st_gid [%u] b->st_gid [%u]\n",
					a->st_gid, b->st_gid);
		return false;
	}
	return true;
}

static bool xlate_sid2unixids(struct torture_context *tctx, struct smbcli_state *cli,
				int fnum, char *fuse_path,
				char *user_sid, char *group_sid,
				uid_t *uid, gid_t *gid)
{
	NTSTATUS status;
	union smb_setfileinfo set;
	struct security_descriptor *sd;
	struct stat sbuf;
	int rc;

	sd = security_descriptor_dacl_create(tctx,
					0, user_sid, group_sid, NULL);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_OWNER | SECINFO_GROUP;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		torture_comment(tctx, "failed to set security descriptor. status 0x%x\n",
					status);
		return false;
	}

	WAIT_ATTR_CACHE_TIMEOUT;

	rc = stat(fuse_path, &sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get stat info for [%s]. errno [%d]\n",
				fuse_path, errno);
		return false;
	}

	if (uid) *uid = sbuf.st_uid;
	if (gid) *gid = sbuf.st_gid;

	return true;
}

#define ACL_CHOWN_OP		1
#define ACL_CHGRP_OP		2
#define ACL_CHMOD_OP		3

char *acl_op_tostr(int op)
{
	switch(op) {
		case ACL_CHOWN_OP: return "ACL_CHOWN_OP";
		case ACL_CHGRP_OP: return "ACL_CHGRP_OP";
		case ACL_CHMOD_OP: return "ACL_CHMOD_OP";
		default:	   return "Invalid op";
	}
}

static bool verify_xattr_del_4_setattr(struct torture_context *tctx, struct smbcli_state *cli,
					int op, int fnum, struct security_descriptor *orig_sd,
					char *fuse_path, char *fsmb_mnt_path,  uid_t uid, gid_t gid, mode_t mode)
{
	NTSTATUS status;
	union smb_setfileinfo set;
	union smb_setfileinfo sfinfo;
	int rc;

	sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFO;
	sfinfo.basic_info.in.file.fnum = fnum;
	sfinfo.basic_info.in.attrib = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN;
	status = smb_raw_setfileinfo(cli->tree, &sfinfo);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		torture_comment(tctx, "failed to set hidden and readonly attribute. status 0x%x\n",
					status);
		return false;
	}

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL;
	set.set_secdesc.in.sd = orig_sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		torture_comment(tctx, "failed to set security descriptor. status 0x%x\n",
					status);
		return false;
	}

	WAIT_ATTR_CACHE_TIMEOUT;

	/* chown through FUSE and verify that NTACL xattrs has been deleted */
	rc = getxattr(fsmb_mnt_path, "security.NTACL", NULL, 0);
	if (rc < 0) {
		torture_comment(tctx, "failed to fetch the security.NTACL XATTR for [%s]. errno %d\n",
			fuse_path, errno);
		return false;
	}

	rc = getxattr(fuse_path, "user.DOSATTRIB", NULL, 0);
	if (rc < 0) {
		torture_comment(tctx, "failed to fetch the user.DOSATTRIB XATTR for [%s]. errno %d\n",
					fuse_path, errno);
		return false;
	}

	switch(op) {
		case ACL_CHOWN_OP:
			rc = chown(fuse_path, uid, -1);
			break;
		case ACL_CHGRP_OP:
			rc = chown(fuse_path, -1, gid);
			break;
		case ACL_CHMOD_OP:
			rc = chmod(fuse_path, mode);
			break;
		default:
			torture_comment(tctx, "invalid setattr operation [%d] on path [%s] for ACL test.\n",
							op, fuse_path);
			return false;
	}

	if (rc) {
		torture_comment(tctx, "failed to %s path [%s] to owner [%u] | group [%u] | mode [%0]. errno [%d]\n",
					acl_op_tostr(op), fuse_path, uid, gid, mode, errno);
		return false;
	}

	rc = getxattr(fsmb_mnt_path, "security.NTACL", NULL, 0);
	if (rc != -1 || errno != ENODATA) {
		torture_comment(tctx, "after %s path [%s] security.NTACL XATTR was not deleted. errno %d\n",
					acl_op_tostr(op), fuse_path, errno);
		return false;
	}

	rc = getxattr(fsmb_mnt_path, "user.DOSATTRIB", NULL, 0);
	if (rc != -1 || errno != ENODATA) {
		torture_comment(tctx, "after %s path [%s] user.DOSATTRIB XATTR was not deleted. errno %d\n",
					acl_op_tostr(op), fuse_path, errno);
		return false;
	}
	return true;
}

static mode_t unix_perms_to_acl_perms(mode_t mode, int r_mask, int w_mask, int x_mask)
{
	mode_t ret = 0;

	if (mode & r_mask)
		ret |= S_IRUSR;
	if (mode & w_mask)
		ret |= S_IWUSR;
	if (mode & x_mask)
		ret |= S_IXUSR;

	return ret;
}

// This is define in sourc3/smbd/posix_acl.c
#ifndef ALL_ACE_PERMS
#define ALL_ACE_PERMS (S_IRUSR|S_IWUSR|S_IXUSR)
#endif

// These are defined in source3/include/smb.h but including smb.h creates conflicts.
#ifndef UNIX_ACCESS_RWX
#define UNIX_ACCESS_RWX         FILE_GENERIC_ALL
#endif

#ifndef UNIX_ACCESS_R
#define UNIX_ACCESS_R           FILE_GENERIC_READ
#endif

#ifndef UNIX_ACCESS_W
#define UNIX_ACCESS_W           FILE_GENERIC_WRITE
#endif

#ifndef UNIX_ACCESS_X
#define UNIX_ACCESS_X           FILE_GENERIC_EXECUTE
#endif

#ifndef UNIX_DIRECTORY_ACCESS_RWX
#define UNIX_DIRECTORY_ACCESS_RWX               FILE_GENERIC_ALL
#endif

#ifndef UNIX_DIRECTORY_ACCESS_R
#define UNIX_DIRECTORY_ACCESS_R                 FILE_GENERIC_READ
#endif

#ifndef UNIX_DIRECTORY_ACCESS_W
#define UNIX_DIRECTORY_ACCESS_W                 (FILE_GENERIC_WRITE|FILE_DELETE_CHILD)
#endif

#ifndef UNIX_DIRECTORY_ACCESS_X
#define UNIX_DIRECTORY_ACCESS_X                 FILE_GENERIC_EXECUTE
#endif

/*
 * The following functions are copied from source3/smbd/posix_acls.c
 */
uint32_t map_canon_ace_perms(bool is_map_full_control,
				mode_t perms,
				bool directory_ace)
{
	uint32_t nt_mask = 0;
	bool lp_dos_filemode = true; // "dos filemode" smb.conf is set to true by vfs_acl_xattr

	if (is_map_full_control && ((perms & ALL_ACE_PERMS) == ALL_ACE_PERMS)) {
		if (directory_ace) {
			nt_mask = UNIX_DIRECTORY_ACCESS_RWX;
		} else {
			nt_mask = (UNIX_ACCESS_RWX & ~DELETE_ACCESS);
		}
	} else if ((perms & ALL_ACE_PERMS) == (mode_t)0) {
		/*
		 * Windows NT refuses to display ACEs with no permissions in them (but
		 * they are perfectly legal with Windows 2000). If the ACE has empty
		 * permissions we cannot use 0, so we use the otherwise unused
		 * WRITE_OWNER permission, which we ignore when we set an ACL.
		 * We abstract this into a #define of UNIX_ACCESS_NONE to allow this
		 * to be changed in the future.
		 */

		nt_mask = 0;
	} else {
		if (directory_ace) {
			nt_mask |= ((perms & S_IRUSR) ? UNIX_DIRECTORY_ACCESS_R : 0 );
			nt_mask |= ((perms & S_IWUSR) ? UNIX_DIRECTORY_ACCESS_W : 0 );
			nt_mask |= ((perms & S_IXUSR) ? UNIX_DIRECTORY_ACCESS_X : 0 );
		} else {
			nt_mask |= ((perms & S_IRUSR) ? UNIX_ACCESS_R : 0 );
			nt_mask |= ((perms & S_IWUSR) ? UNIX_ACCESS_W : 0 );
			nt_mask |= ((perms & S_IXUSR) ? UNIX_ACCESS_X : 0 );
		}
	}

	if ((perms & S_IWUSR) && lp_dos_filemode) {
		nt_mask |= (SEC_STD_WRITE_DAC|SEC_STD_WRITE_OWNER|DELETE_ACCESS);
	}

	DEBUG(10,("map_canon_ace_perms: Mapped (UNIX) %x to (NT) %x\n",
			(unsigned int)perms, (unsigned int)nt_mask ));

	return nt_mask;
}



static void perms_to_access_masks(bool is_map_full_control, bool is_directory, mode_t perms,
				uint32_t *u_access_mask, uint32_t *g_access_mask,
				uint32_t *o_access_mask)
{
	mode_t acl_perms;

	if (u_access_mask) {
		acl_perms = unix_perms_to_acl_perms(perms, S_IRUSR, S_IWUSR, S_IXUSR);
		*u_access_mask = map_canon_ace_perms(is_map_full_control, acl_perms, is_directory);
	}

	if (g_access_mask) {
		acl_perms = unix_perms_to_acl_perms(perms, S_IRGRP, S_IWGRP, S_IXGRP);
		*g_access_mask = map_canon_ace_perms(is_map_full_control, acl_perms, is_directory);
	}

	if (o_access_mask) {
		acl_perms = unix_perms_to_acl_perms(perms, S_IROTH, S_IWOTH, S_IXOTH);
		*o_access_mask = map_canon_ace_perms(is_map_full_control, acl_perms, is_directory);
	}
}

static bool test_fuse_internal(struct torture_context *tctx, struct smbcli_state *cli, bool is_directory)
{
	NTSTATUS status;
//	const char *fname = BASEDIR "\\" SET_OWNER_FNAME;
//	const char *dname = BASEDIR "\\" SET_OWNER_DNAME;
	char smb_path_name[512];
	union smb_open io;
	bool ret = true;
	const char *fuse_mnt = NULL;
	const char *fsmb_mnt = NULL;
	int fnum = -1;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *orig_sd;
	const char* bgroup = NULL;
	const char* buser_name = NULL;
	char accnt_name[512];
	char *user_sid1, *user_sid2, *user_sid3;
	char *group_sid1, *group_sid2, *group_sid3;
	char fuse_path[512];
	char fsmb_mnt_path[512];
	int fuse_fd;
	struct stat orig_sbuf, exp_sbuf, new_sbuf;
	uint32_t u_access_mask, g_access_mask, o_access_mask;
	char setgid_path[512];
	char setgid_lpath[512];
	char setgid_fpath[512];
	char setgid_lfpath[512];
	char *cur_path_elem = NULL;
	uid_t uids[MAX_DIR_LEVELS];
	gid_t gids[MAX_DIR_LEVELS];
	bool is_map_full_control = true;
	int i;
	int rc;

	fuse_mnt = torture_setting_string(tctx, ACL_FUSE_MNT, NULL);
	if (!fuse_mnt) {
		torture_comment(tctx, "%s parameter is required\n", ACL_FUSE_MNT);
		FAIL_UNLESS(fuse_mnt);
		return false;
	}
	fsmb_mnt = torture_setting_string(tctx, ACL_FSMB_MNT, NULL);
	if (!fsmb_mnt) {
		torture_comment(tctx, "%s parameter is required\n", ACL_FSMB_MNT);
		FAIL_UNLESS(fsmb_mnt);
		return false;
	}

	if (strequal(torture_setting_string(tctx, ACL_MAP_FCT, NULL), "false")) {
		is_map_full_control = false;
	}

	bgroup = torture_setting_string(tctx, ACL_MLT_GRP, NULL);
	if (!bgroup) {
		torture_comment(tctx, "%s parameter is required\n", ACL_MLT_GRP);
		FAIL_UNLESS(bgroup);
		return false;
	}
	snprintf(accnt_name, 512, "%s1", bgroup);
	group_sid1 = get_group_sid_str(tctx, accnt_name);
	if (!group_sid1) {
		torture_comment(tctx, "failed to get SID for group [%s]\n", accnt_name);
		FAIL_UNLESS(group_sid1);
		return false;
	}
	snprintf(accnt_name, 512, "%s2", bgroup);
	group_sid2 = get_group_sid_str(tctx, accnt_name);
	if (!group_sid2) {
		torture_comment(tctx, "failed to get SID for group [%s]\n", accnt_name);
		FAIL_UNLESS(group_sid2);
		return false;
	}
	snprintf(accnt_name, 512, "%s3", bgroup);
	group_sid3 = get_group_sid_str(tctx, accnt_name);
	if (!group_sid3) {
		torture_comment(tctx, "failed to get SID for group [%s]\n", accnt_name);
		FAIL_UNLESS(group_sid3);
		return false;
	}

	buser_name = torture_setting_string(tctx, ACL_MLT_USR, NULL);
	if (!buser_name) {
		torture_comment(tctx, "%s parameter is required\n", ACL_MLT_USR);
		FAIL_UNLESS(buser_name);
		return false;
	}

	snprintf(accnt_name, 512, "%s1", buser_name);

	user_sid1 = get_user_sid_str(tctx, accnt_name);
	if (!user_sid1) {
		torture_comment(tctx, "failed to get SID for user [%s]\n", accnt_name);
		FAIL_UNLESS(user_sid1);
		return false;
	}
	snprintf(accnt_name, 512, "%s2", buser_name);
	user_sid2 = get_user_sid_str(tctx, accnt_name);
	if (!user_sid2) {
		torture_comment(tctx, "failed to get SID for user [%s]\n", accnt_name);
		FAIL_UNLESS(user_sid2);
		return false;
	}
	snprintf(accnt_name, 512, "%s3", buser_name);
	user_sid3 = get_user_sid_str(tctx, accnt_name);
	if (!user_sid3) {
		torture_comment(tctx, "failed to get SID for user [%s]\n", accnt_name);
		FAIL_UNLESS(user_sid3);
		return false;
	}

	if (!torture_setup_dir(cli, BASEDIR))
		return false;

	if (is_directory) {
		snprintf(smb_path_name, 512, "%s\\%s", BASEDIR, SET_OWNER_DNAME);
		torture_comment(tctx, "=create test directory [%s]\n", smb_path_name);
	} else {
		snprintf(smb_path_name, 512, "%s\\%s", BASEDIR, SET_OWNER_FNAME);
		torture_comment(tctx, "=create test file [%s]\n", smb_path_name);
	}

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC |
					 SEC_STD_WRITE_OWNER | SEC_FILE_WRITE_ATTRIBUTE;
	io.ntcreatex.in.create_options = (is_directory)? FILE_DIRECTORY_FILE : 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access =
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = smb_path_name;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	WAIT_ATTR_CACHE_TIMEOUT;

	torture_comment(tctx, "=fetch and save the original security\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	orig_sd = q.query_secdesc.out.sd;

	/* open the file through fuse mount point and get stat */
	torture_comment(tctx, "=open and save the stat info of [%s] through FUSE mount point\n",
				smb_path_name);
	if (is_directory) {
		snprintf(fuse_path, 512, "%s/%s/%s", fuse_mnt, BASEDIR_NAME, SET_OWNER_DNAME);
		snprintf(fsmb_mnt_path, 512, "%s/%s/%s", fsmb_mnt, BASEDIR_NAME, SET_OWNER_DNAME);
	} else {
		snprintf(fuse_path, 512, "%s/%s/%s", fuse_mnt, BASEDIR_NAME, SET_OWNER_FNAME);
		snprintf(fsmb_mnt_path, 512, "%s/%s/%s", fsmb_mnt, BASEDIR_NAME, SET_OWNER_FNAME);
	}

	rc = stat(fuse_path, &orig_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get origignal stat info for path [%s]. errno [%d]\n",
					fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}

	/* set the group as the owner of the file */
	torture_comment(tctx, "+set group sid [%s] as owner and owning group\n", group_sid1);
	sd = security_descriptor_dacl_create(tctx,
					0, group_sid1, NULL, NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_OWNER;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	WAIT_ATTR_CACHE_TIMEOUT;

	/* verify through fuse_mnt that the stat has not been changed */
	torture_comment(tctx, " verify that stat info does not change in respond to the new sd\n");
	rc = stat(fuse_path, &new_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get new stat info for path [%s]. errno [%d]\n",
					fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}

	if (!verify_perm(tctx, &orig_sbuf, &new_sbuf)) {
		torture_comment(tctx, "unexpected owner, group, or permission mode changed for file [%s]\n",
					fuse_path);
		ret = false;
		FAIL_UNLESS(ret);
		goto done;
	}

	/* verify that the file has the new security descriptor */
	torture_comment(tctx, "-also confirm that file has the new sd that we just set\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_OWNER;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd);

	/* set EVERYONE as the owner of the file */
	torture_comment(tctx, "+set SID_WORLD as owner and group\n");
	sd = security_descriptor_dacl_create(tctx,
					0, SID_WORLD, SID_WORLD,
					NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_OWNER | SECINFO_GROUP;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	WAIT_ATTR_CACHE_TIMEOUT;

	/* verify through fuse_mnt that the stat has not been changed */
	torture_comment(tctx, " verify that stat info does not change in respond to the new sd\n");
	rc = stat(fuse_path, &new_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get new stat info for path [%s]. errno [%d]\n",
				fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}
	if (!verify_perm(tctx, &orig_sbuf, &new_sbuf)) {
		torture_comment(tctx, "unexpected owner, group, or permission mode changed for file [%s]\n",
					fuse_path);
		ret = false;
		FAIL_UNLESS(ret);
		goto done;
	}

	torture_comment(tctx, "-also verify that file has the new sd that we just set\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_OWNER | SECINFO_GROUP;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd);

	/*
	 * Set the SD to have only one user ACE that does not match the current owner.
	 * The permission for the user is WRITE (200).
	 * The expected end result should be perms of 000, however, Samba will add
	 * S_IRUSR (4) so the permission will become 400.
	 */
	torture_comment(tctx, "+set sd to have user ACE where the user is not the owner, ACE has WRITE perms\n");
	sd = security_descriptor_dacl_create(tctx,
						0, NULL, NULL,
						user_sid1,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_WRITE | SEC_STD_ALL,
						0,
						NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	WAIT_ATTR_CACHE_TIMEOUT;

	/* verify through fuse_mnt that the stat has not been changed */
	torture_comment(tctx, "-verify that permission should become 000 + S_IRUSR\n");
	rc = stat(fuse_path, &new_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get new stat info for path [%s]. errno [%d]\n",
				fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}
	memcpy(&exp_sbuf, &orig_sbuf, sizeof(orig_sbuf));

	// The end result mode should be 0, however, Samba will set the READ perms 4 for user
	if (is_directory)
		exp_sbuf.st_mode = (mode_t)0700;
	else
		exp_sbuf.st_mode = (mode_t)0400;
	if (!verify_perm(tctx, &exp_sbuf, &new_sbuf)) {
		torture_comment(tctx, "unexpected owner, group, or permission mode changed for file [%s]\n",
					fuse_path);
		ret = false;
		FAIL_UNLESS(ret);
		goto done;
	}

	/*
	 * Set the SD to have only one user ACE that does not match the current owner.
	 * The permission for the user is EXECUTE (100).
	 * The expected end result should be perms of 000, however, Samba will add
	 * S_IRUSR (4) so the permission will become 400.
	 */
	torture_comment(tctx, "+repeat set sd to have non-owner user ACE, but ACE has EXEC perms\n");
	sd = security_descriptor_dacl_create(tctx,
						0, NULL, NULL,
						user_sid1,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_EXECUTE,
						0,
						NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	WAIT_ATTR_CACHE_TIMEOUT;

	/* verify through fuse_mnt that the stat has not been changed */
	torture_comment(tctx, "-again, verify that permission should become 000 + S_IRUSR\n");
	rc = stat(fuse_path, &new_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get new stat info for path [%s]. errno [%d]\n",
				fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}
	memcpy(&exp_sbuf, &orig_sbuf, sizeof(orig_sbuf));

	// The end result mode should be 0, however, Samba will set the READ perms 4 for user
	if (is_directory)
		exp_sbuf.st_mode = (mode_t)0700;
	else
		exp_sbuf.st_mode = (mode_t)0400;
	if (!verify_perm(tctx, &exp_sbuf, &new_sbuf)) {
		torture_comment(tctx, "unexpected owner, group, or permission mode changed for file [%s]\n",
					fuse_path);
		ret = false;
		FAIL_UNLESS(ret);
		goto done;
	}

	/* change permission of EVERYONE to READ */
	torture_comment(tctx, "+add EVERYONE ACE with READ permission\n");
	sd = security_descriptor_dacl_create(tctx,
						0, NULL, NULL,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_READ,
						0,
						NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	WAIT_ATTR_CACHE_TIMEOUT;

	/* verify through fuse_mnt that the stat has not been changed */
	torture_comment(tctx, "-verify that permission became 004 + S_IRUSR (added by Samba)\n");
	rc = stat(fuse_path, &new_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get new stat info for path [%s]. errno [%d]\n",
				fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}
	memcpy(&exp_sbuf, &orig_sbuf, sizeof(orig_sbuf));

	if (is_directory)
		exp_sbuf.st_mode = (mode_t)0704;
	else
		exp_sbuf.st_mode = (mode_t)0404;
	if (!verify_perm(tctx, &exp_sbuf, &new_sbuf)) {
		torture_comment(tctx, "unexpected owner, group, or permission mode changed for file [%s]\n",
					fuse_path);
		ret = false;
		FAIL_UNLESS(ret);
		goto done;
	}

	/* change permission of EVERYONE to WRITE */
	torture_comment(tctx, "+add EVERYONE ACE with WRITE permission\n");
	sd = security_descriptor_dacl_create(tctx,
						0, NULL, NULL,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_WRITE,
						0,
						NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	WAIT_ATTR_CACHE_TIMEOUT;

	/* verify through fuse_mnt that the stat has not been changed */
	torture_comment(tctx, "-verify that permission became 002 + S_IRUSR (402)\n");
	rc = stat(fuse_path, &new_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get new stat info for path [%s]. errno [%d]\n",
				fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}
	memcpy(&exp_sbuf, &orig_sbuf, sizeof(orig_sbuf));

	if (is_directory)
		exp_sbuf.st_mode = (mode_t)0702;
	else
		exp_sbuf.st_mode = (mode_t)0402;
	if (!verify_perm(tctx, &exp_sbuf, &new_sbuf)) {
		torture_comment(tctx, "unexpected owner, group, or permission mode changed for file [%s]\n",
					fuse_path);
		ret = false;
		FAIL_UNLESS(ret);
		goto done;
	}

	/* Retrieve corresponding Group GID */
	ret = xlate_sid2unixids(tctx, cli, fnum, fuse_path, user_sid1, group_sid1, &uids[0], &gids[0]);
	if (!ret) {
		torture_comment(tctx, "failed to translate sids u [%s] g [%s] to uid and gid\n",
					user_sid1, group_sid1);
		FAIL_UNLESS(ret);
		goto done;
	}
	ret = xlate_sid2unixids(tctx, cli, fnum, fuse_path, user_sid2, group_sid2, &uids[1], &gids[1]);
	if (!ret) {
		torture_comment(tctx, "failed to translate sids u [%s] g [%s] to uid and gid\n",
					user_sid2, group_sid2);
		FAIL_UNLESS(ret);
		goto done;
	}
	ret = xlate_sid2unixids(tctx, cli, fnum, fuse_path, user_sid3, group_sid3, &uids[2], &gids[2]);
	if (!ret) {
		torture_comment(tctx, "failed to translate sids u [%s] g [%s] to uid and gid\n",
					user_sid3, group_sid3);
		FAIL_UNLESS(ret);
		goto done;
	}

	/* change group using group ACE */
	torture_comment(tctx, "=sid [%s] maps to gid [%u]\n", group_sid1, gids[0]);
	torture_comment(tctx, "+change owning group by specifying ACL with one group ACE - group sid[%s]\n",
				group_sid1);
	sd = security_descriptor_dacl_create(tctx,
						0, user_sid1, NULL,
						group_sid1,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_WRITE | SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
						0,
						NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_OWNER | SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	WAIT_ATTR_CACHE_TIMEOUT;

	/* verify through fuse_mnt that the stat has not been changed */
	torture_comment(tctx, "-verify that the owning group has been changed to gid of group sid [%s]\n");
	rc = stat(fuse_path, &new_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get new stat info for path [%s]. errno [%d]\n",
					fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}
	memcpy(&exp_sbuf, &orig_sbuf, sizeof(orig_sbuf));

	if (is_directory)
		exp_sbuf.st_mode = (mode_t)0760;
	else
		exp_sbuf.st_mode = (mode_t)0460;
	exp_sbuf.st_uid = uids[0];
	exp_sbuf.st_gid = gids[0];
	if (!verify_perm(tctx, &exp_sbuf, &new_sbuf)) {
		torture_comment(tctx, "unexpected owner, group, or permission mode changed for file [%s]\n",
					fuse_path);
		ret = false;
		FAIL_UNLESS(ret);
		goto done;
	}

	/* change to group2 using the group ACE in the ACL, this time with 3 ACEs, owner, group, and other */
	torture_comment(tctx, "=sid [%s] maps to gid [%u]\n", group_sid2, gids[1]);
	torture_comment(tctx, "+change owning group by specifying ACL with user, every, and group ACEs - group sid[%s]\n",
				group_sid2);
	sd = security_descriptor_dacl_create(tctx,
						0, user_sid2, NULL,
						user_sid2,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_WRITE | SEC_STD_ALL,
						0,
						group_sid2,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_WRITE | SEC_STD_ALL,
						0,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_ALL | SEC_STD_ALL,
						0,
						NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_OWNER | SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	WAIT_ATTR_CACHE_TIMEOUT;

	/*
	 * verify through fuse_mnt that the stat info has been updated to reflect the
	 * new group and corresponding perms of owner and everyone.
	 */
	torture_comment(tctx, "-verify that owning grp has changed to [%u] and perms has been updated to 227 + S_IRUSR (627)\n",
				gids[1]);
	rc = stat(fuse_path, &new_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get new stat info for path [%s]. errno [%d]\n",
				fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}
	memcpy(&exp_sbuf, &orig_sbuf, sizeof(orig_sbuf));

	if (is_directory)
		exp_sbuf.st_mode = (mode_t)0727;
	else
		exp_sbuf.st_mode = (mode_t)0627;
	exp_sbuf.st_uid = uids[1];
	exp_sbuf.st_gid = gids[1];
	if (!verify_perm(tctx, &exp_sbuf, &new_sbuf)) {
		torture_comment(tctx, "unexpected owner, group, or permission mode changed for file [%s]\n",
					fuse_path);
		ret = false;
		FAIL_UNLESS(ret);
		goto done;
	}


	/*
	 * change to group3 using the the group ACE in the ACL.
	 * ensure the CREATOR OWNER and CREATOR GROUP ACEs adds additional permissions
	 * to owner and owning group permissions.
	 */
	torture_comment(tctx, "+repeat - change to group [%s] using 5 ACEs, owner, group, everyone\n", group_sid3);
	torture_comment(tctx, "     in addition to CREATOR OWNER, and CREATOR GROUP ACEs\n");
	sd = security_descriptor_dacl_create(tctx,
						0, user_sid2, NULL,
						user_sid2,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_WRITE | SEC_STD_ALL,
						0,
						group_sid3,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_WRITE | SEC_STD_ALL,
						0,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_ALL | SEC_STD_ALL,
						0,
						SID_CREATOR_OWNER,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_EXECUTE | SEC_STD_ALL,
						0,
						SID_CREATOR_GROUP,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
						0,
						NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_OWNER | SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	WAIT_ATTR_CACHE_TIMEOUT;

	/* verify through fuse_mnt that the stat has not been changed */
	torture_comment(tctx, "-verify that owning grp has changed to [%u]\n", gids[2]);
	/*
	 * for files CREATOR OWNER and CREATOR GROUP perms get added to owner ace and group ace.
	 * However, this is done by the Application layer (Explorer.exe) rather than Samba.
	 * for directory, CREATOR OWNER and CREATOR GROUP aces are used for inheritance.
	 */
	if (!is_directory) {
		torture_comment(tctx, "    also, perms from CREATOR OWNER were added to owner ACE\n");
		torture_comment(tctx, "    perms from CREATOR GROUP were added to owning group ACE\n");
	}
	rc = stat(fuse_path, &new_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get new stat info for path [%s]. errno [%d]\n",
				fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}
	memcpy(&exp_sbuf, &orig_sbuf, sizeof(orig_sbuf));

	/*
	 * for files CREATOR OWNER and CREATOR GROUP perms get added to owner ace and group ace.
	 * However, this is done by the Application layer (Explorer.exe) rather than Samba.
	 * for directory, CREATOR OWNER and CREATOR GROUP aces are used for inheritance.
	 */
	if (is_directory)
		exp_sbuf.st_mode = (mode_t)0727;
	else
		exp_sbuf.st_mode = (mode_t)0627;
	exp_sbuf.st_uid = uids[1];
	exp_sbuf.st_gid = gids[2];
	if (!verify_perm(tctx, &exp_sbuf, &new_sbuf)) {
		torture_comment(tctx, "unexpected owner, group, or permission mode changed for file [%s]\n",
					fuse_path);
		ret = false;
		FAIL_UNLESS(ret);
		goto done;
	}

	/* set security descriptor with more than 1 group ACEs, verify the owning group is unchanged */
	torture_comment(tctx, "+set sd with more than 1 group ACEs\n");
	sd = security_descriptor_dacl_create(tctx,
						0, user_sid2, NULL,
						user_sid2,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_WRITE | SEC_STD_ALL,
						0,
						group_sid3,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_WRITE | SEC_STD_ALL,
						0,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_ALL | SEC_STD_ALL,
						0,
						group_sid1,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
						0,
						group_sid2,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
						0,
						NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_OWNER | SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	WAIT_ATTR_CACHE_TIMEOUT;

	/* verify through fuse_mnt that the stat has not been changed */
	torture_comment(tctx, "-verify that group is unchanged from gid [%u]\n", gids[2]);
	rc = stat(fuse_path, &new_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get new stat info for path [%s]. errno [5d]\n",
				fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}
	memcpy(&exp_sbuf, &orig_sbuf, sizeof(orig_sbuf));

	if (is_directory)
		exp_sbuf.st_mode = (mode_t)0727;
	else
		exp_sbuf.st_mode = (mode_t)0627;
	exp_sbuf.st_uid = uids[1];
	exp_sbuf.st_gid = gids[2];
	if (!verify_perm(tctx, &exp_sbuf, &new_sbuf)) {
		torture_comment(tctx, "unexpected owner, group, or permission mode changed for file [%s]\n",
					fuse_path);
		ret = false;
		FAIL_UNLESS(ret);
		goto done;
	}

	/* chown through FUSE and verify that NTACL xattrs has been deleted */
	torture_comment(tctx, "+chown the path [%s] and verify that XATTR security.NTACL was removed\n",
				fuse_path);
	ret = verify_xattr_del_4_setattr(tctx, cli, ACL_CHOWN_OP, fnum, orig_sd,
					fuse_path, fsmb_mnt_path, uids[0], 0, 0);
	if (!ret) {
		torture_comment(tctx, "failed to verify xattrs were deleted after chown [%s]\n",
					fuse_path);
		FAIL_UNLESS(ret);
		goto done;
	}

	/* chgrp through FUSE and verify that NTACL xattrs has been deleted */
	torture_comment(tctx, "+chgrp the path [%s] and verify that XATTR security.NTACL was removed\n",
				fuse_path);
	ret = verify_xattr_del_4_setattr(tctx, cli, ACL_CHGRP_OP, fnum, orig_sd,
					fuse_path, fsmb_mnt_path, 0, gids[0], 0);
	if (!ret) {
		torture_comment(tctx, "failed to verify xattrs were deleted after chgrp [%s]\n",
					fuse_path);
		FAIL_UNLESS(ret);
		goto done;
	}

	/* chmod through FUSE and verify that NTACL xattrs has been deleted */
	torture_comment(tctx, "+chmod the path [%s] and verify that XATTR security.NTACL was removed\n",
				fuse_path);
	ret = verify_xattr_del_4_setattr(tctx, cli, ACL_CHMOD_OP, fnum, orig_sd,
					fuse_path, fsmb_mnt_path, 0, 0, (mode_t)767);
	if (!ret) {
		torture_comment(tctx, "failed to verify xattrs were delted after chmod [%s]\n",
					fuse_path);
		FAIL_UNLESS(ret);
		goto done;
	}

	/* For FILES - verify the default sec_desc that SAMBA generated from POSIX permission mode bits */
	if (is_directory) {
		snprintf(smb_path_name, 512, "%s\\%s", BASEDIR, DEF_ACL_DNAME);
		torture_comment(tctx, "test default acl - create directory [%s]\n", smb_path_name);
	} else {
		snprintf(smb_path_name, 512, "%s\\%s", BASEDIR, DEF_ACL_FNAME);
		torture_comment(tctx, "test default acl - create file [%s]\n", smb_path_name);
	}

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC | SEC_STD_WRITE_OWNER;
	io.ntcreatex.in.create_options = (is_directory) ? FILE_DIRECTORY_FILE : 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access =
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = smb_path_name;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	WAIT_ATTR_CACHE_TIMEOUT;

	snprintf(fuse_path, 512, "%s/%s/%s", fuse_mnt, BASEDIR_NAME, (is_directory)? DEF_ACL_DNAME : DEF_ACL_FNAME);
	torture_comment(tctx, "=execute chown, and chmod through [%s] to trigger deletion of security.NTACL xattr\n",
				fuse_path);
	rc = chown(fuse_path, uids[0], gids[0]);
	if (rc) {
		torture_comment(tctx, "failed to chown for %s with uid [%u] gid [%u]\n",
					fuse_path, uids[0], gids[0]);
		FAIL_UNLESS(rc == 0);
		goto done;
	}
	orig_sbuf.st_mode = (is_directory)? (mode_t)0744 : (mode_t)0444;
	rc = chmod(fuse_path, orig_sbuf.st_mode);
	if (rc) {
		torture_comment(tctx, "failed to chmod [%s] to [%o]\n",
					fuse_path, orig_sbuf.st_mode);
		FAIL_UNLESS(rc == 0);
		goto done;
	}

	rc = stat(fuse_path, &orig_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get orig stat info for path [%s]. errno [%d]\n",
				fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}

	perms_to_access_masks(is_map_full_control, is_directory,
					orig_sbuf.st_mode, &u_access_mask, &g_access_mask, &o_access_mask);

	if (is_directory) {
		sd = security_descriptor_dacl_create(tctx,
						0, user_sid1 , group_sid1,
						user_sid1,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						u_access_mask,
						0,
						group_sid1,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						g_access_mask,
						0,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						o_access_mask,
						0,
						SID_CREATOR_OWNER,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_ALL | SEC_STD_ALL,
						SEC_ACE_FLAG_OBJECT_INHERIT | SEC_ACE_FLAG_CONTAINER_INHERIT |
							SEC_ACE_FLAG_INHERIT_ONLY,
						SID_CREATOR_GROUP,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_RIGHTS_FILE_READ | SEC_RIGHTS_FILE_EXECUTE,
						SEC_ACE_FLAG_OBJECT_INHERIT | SEC_ACE_FLAG_CONTAINER_INHERIT |
							SEC_ACE_FLAG_INHERIT_ONLY,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						o_access_mask | SEC_RIGHTS_FILE_EXECUTE,
						SEC_ACE_FLAG_OBJECT_INHERIT | SEC_ACE_FLAG_CONTAINER_INHERIT |
							SEC_ACE_FLAG_INHERIT_ONLY,
						NULL);
	} else {
		sd = security_descriptor_dacl_create(tctx,
						0, user_sid1, group_sid1,
						user_sid1,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						u_access_mask,
						0,
						group_sid1,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						g_access_mask,
						0,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						o_access_mask,
						0,
						NULL);
	}

	/* verify that the file has the new security descriptor */
	torture_comment(tctx, "-verify that file/dir has the new default sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL;
	status = smb_raw_fileinfo(cli->tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd);

	/* Create subdirs 3 levels deep where each level is owned by a different group to verify SETGID bit*/
	torture_comment(tctx, "+create directories 3 levels deep to test the SETGID bit\n");
	snprintf(setgid_path, 512, "%s", BASEDIR);
	snprintf(setgid_lpath, 512, "%s/%s", fuse_mnt, BASEDIR_NAME); //setgid linux path

	if (!is_directory) {
		snprintf(setgid_fpath, 512, "%s", BASEDIR);  //setgid file path through samba
		snprintf(setgid_lfpath, 512, "%s/%s", fuse_mnt, BASEDIR_NAME); // setgid linux path for file
	}

	rc = stat(setgid_lpath, &orig_sbuf);
	if (rc) {
		torture_comment(tctx, "failed to get orig stat info for path [%s]. errno [%d]\n",
				fuse_path, errno);
		FAIL_UNLESS(rc == 0);
		ret = false;
		goto done;
	}
	torture_comment(tctx, "=parent directory [%s] has gid [%u]\n", setgid_lpath, orig_sbuf.st_gid);
	for (i = 1; i <= MAX_DIR_LEVELS; i++ ) {
		/* create a file along with the subdirectory */
		if (!is_directory) {
			strncpy(setgid_fpath, setgid_path, strlen(setgid_path));
			cur_path_elem = setgid_fpath + strlen(setgid_path);
			snprintf(cur_path_elem, 512 - strlen(setgid_path), "\\%s%d", SETGID_FNAME, i);

			torture_comment(tctx, " +create child file [%s]\n", setgid_fpath);
			io.generic.level = RAW_OPEN_NTCREATEX;
			io.ntcreatex.in.root_fid.fnum = 0;
			io.ntcreatex.in.flags = 0;
			io.ntcreatex.in.access_mask = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC |
									     SEC_STD_WRITE_OWNER;
			io.ntcreatex.in.create_options = (is_directory)? FILE_DIRECTORY_FILE : 0;
			io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
			io.ntcreatex.in.share_access =
				NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
			io.ntcreatex.in.alloc_size = 0;
			io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
			io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
			io.ntcreatex.in.security_flags = 0;
			io.ntcreatex.in.fname = setgid_fpath;
			status = smb_raw_open(cli->tree, tctx, &io);
			CHECK_STATUS(status, NT_STATUS_OK);

			WAIT_ATTR_CACHE_TIMEOUT;

			/* verify the child file inherited group from parent */
			strncpy(setgid_lfpath, setgid_lpath, strlen(setgid_lpath));
			cur_path_elem = setgid_lfpath + strlen(setgid_lpath);
			snprintf(cur_path_elem, 512 - strlen(setgid_lfpath), "/%s%d", SETGID_FNAME, i);

			torture_comment(tctx, " -verify file [%s] has inherited gid[%u] from parent\n",
					setgid_lfpath, orig_sbuf.st_gid);
			rc = stat(setgid_lfpath, &new_sbuf);
			if (rc) {
				torture_comment(tctx, "failed to get stat info for [%s]. errno [%d]\n",
						setgid_lfpath, errno);
				FAIL_UNLESS(rc == 0);
				ret = false;
				goto done;
			}
		}
		/* create subdirectory */
		cur_path_elem = setgid_path + strlen(setgid_path);
		snprintf(cur_path_elem, 512 - strlen(setgid_path), "\\%s%d", SETGID_DNAME, i);

		torture_comment(tctx, " +create subdirectory [%s]\n", setgid_path);
		io.generic.level = RAW_OPEN_NTCREATEX;
		io.ntcreatex.in.root_fid.fnum = 0;
		io.ntcreatex.in.flags = 0;
		io.ntcreatex.in.access_mask = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC | SEC_STD_WRITE_OWNER;
		io.ntcreatex.in.create_options = FILE_DIRECTORY_FILE;
		io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
		io.ntcreatex.in.share_access =
			NTCREATEX_SHARE_ACCESS_READ |
			NTCREATEX_SHARE_ACCESS_WRITE;
		io.ntcreatex.in.alloc_size = 0;
		io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
		io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
		io.ntcreatex.in.security_flags = 0;
		io.ntcreatex.in.fname = setgid_path;
		status = smb_raw_open(cli->tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		fnum = io.ntcreatex.out.file.fnum;

		WAIT_ATTR_CACHE_TIMEOUT;

		cur_path_elem = setgid_lpath + strlen(setgid_lpath);
		snprintf(cur_path_elem, 512 - strlen(setgid_lpath), "/%s%d", SETGID_DNAME, i);

		/* try to verify that the new directory inherited group from parent */
		torture_comment(tctx, " -verify subdir [%s] has inherited the gid [%u] from parent\n",
				setgid_lpath, orig_sbuf.st_gid);
		rc = stat(setgid_lpath, &new_sbuf);
		if (rc) {
			torture_comment(tctx, "failed to get orig stat info for path [%s]. errno [%d]\n",
					fuse_path, errno);
			FAIL_UNLESS(rc == 0);
			ret = false;
			goto done;
		}

		if (new_sbuf.st_gid != orig_sbuf.st_gid) {
			torture_comment(tctx, "setgid bit - error newly created subdirectory [%s] did not inherit group from parent, exp [%u] got [%u]\n",
					 setgid_lpath, orig_sbuf.st_gid, new_sbuf.st_gid);
			FAIL_UNLESS(new_sbuf.st_gid == orig_sbuf.st_gid);
			ret = false;
			goto done;
		}

		if (i < MAX_DIR_LEVELS) {
			torture_comment(tctx, "=change parent directory [%s] from owning group gid [%u] to [%u]\n",
					setgid_lpath, orig_sbuf.st_gid, gids[i]);
			orig_sbuf.st_gid = gids[i];
			rc = chown(setgid_lpath, -1, gids[i]);
			if (rc != 0) {
				torture_comment(tctx, "failed to chmod [%s] to gid [%u]. errno [%d]\n",
							setgid_lpath, gids[i]);
				FAIL_UNLESS(rc == 0);
				ret = false;
				goto done;
			}
		}

	}

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	if (ret)
		smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}

static bool test_fuse_dir(struct torture_context *tctx, struct smbcli_state *cli) {
	torture_comment(tctx, "TEST FUSE DIRECTORY\n");
	return test_fuse_internal(tctx, cli, true);
}

static bool test_fuse_file(struct torture_context *tctx, struct smbcli_state *cli) {
	torture_comment(tctx, "TEST FUSE FILE\n");
	return test_fuse_internal(tctx, cli, false);
}

#endif


/* 
   basic testing of security descriptor calls
*/
struct torture_suite *torture_raw_acls(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "acls");

	torture_suite_add_1smb_test(suite, "sd", test_sd);
	torture_suite_add_1smb_test(suite, "create_file", test_nttrans_create_file);
	torture_suite_add_1smb_test(suite, "create_dir", test_nttrans_create_dir);
	torture_suite_add_1smb_test(suite, "nulldacl", test_nttrans_create_null_dacl);
	torture_suite_add_1smb_test(suite, "fuse_file", test_fuse_file);
	torture_suite_add_1smb_test(suite, "fuse_dir", test_fuse_dir);
	torture_suite_add_1smb_test(suite, "creator", test_creator_sid);
	torture_suite_add_1smb_test(suite, "generic", test_generic_bits);
	torture_suite_add_1smb_test(suite, "owner", test_owner_bits);
	torture_suite_add_1smb_test(suite, "inheritance", test_inheritance);

	torture_suite_add_1smb_test(suite, "INHERITFLAGS", test_inheritance_flags);
	torture_suite_add_1smb_test(suite, "dynamic", test_inheritance_dynamic);
#if 0
	/* XXX This test does not work against XP or Vista. */
	torture_suite_add_1smb_test(suite, "GETSET", test_sd_get_set);
#endif

	return suite;
}

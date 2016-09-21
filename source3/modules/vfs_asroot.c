/*
   Unix SMB/CIFS implementation.
   Wrap disk only vfs functions to sidestep dodgy compilers.
   Copyright (C) Tim Potter 1998
   Copyright (C) Jeremy Allison 2007

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
#include "system/time.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "ntioctl.h"
#include "smbprofile.h"
#include "../libcli/security/security.h"
#include "passdb/lookup_sid.h"
#include "source3/include/msdfs.h"
#include "librpc/gen_ndr/ndr_dfsblobs.h"
#include "lib/util/tevent_unix.h"
#include "lib/asys/asys.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/sys_rw.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define BECOME_ROOT_IF_NEEDED(needed)	do { \
						const struct security_unix_token *current_user_ut; \
						current_user_ut = get_current_utok(handle->conn); \
						if (current_user_ut->uid != 0 || current_user_ut->gid != 0) { \
							become_root(); \
							needed = true; \
						} \
					} while(0)


/* Directory operations */

static DIR *vfs_asroot_opendir(vfs_handle_struct *handle, const char *fname, const char *mask, uint32_t attr)
{
	DIR *result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_OPENDIR(handle, fname, mask, attr);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static DIR *vfs_asroot_fdopendir(vfs_handle_struct *handle,
			files_struct *fsp,
			const char *mask,
			uint32_t attr)
{
	DIR *result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static int vfs_asroot_rmdir(vfs_handle_struct *handle, const char *path)
{
	int result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_RMDIR(handle, path);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

/* File operations */

static int vfs_asroot_rename(vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname_src,
			  const struct smb_filename *smb_fname_dst)
{
	int result = -1;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_RENAME(handle, smb_fname_src, smb_fname_dst);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}
static int vfs_asroot_stat(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname)
{
	int result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_STAT(handle, smb_fname);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static int vfs_asroot_fstat(vfs_handle_struct *handle, files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	int result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static int vfs_asroot_lstat(vfs_handle_struct *handle,
			    struct smb_filename *smb_fname)
{
	int result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_LSTAT(handle, smb_fname);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static int vfs_asroot_unlink(vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname)
{
	int result = -1;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_UNLINK(handle, smb_fname);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static int vfs_asroot_chmod(vfs_handle_struct *handle, const char *path, mode_t mode)
{
	int result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_CHMOD(handle, path, mode);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static int vfs_asroot_fchmod(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	int result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static int vfs_asroot_chown(vfs_handle_struct *handle, const char *path, uid_t uid, gid_t gid)
{
	int result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_CHOWN(handle, path, uid, gid);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static int vfs_asroot_fchown(vfs_handle_struct *handle, files_struct *fsp, uid_t uid, gid_t gid)
{
	int result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static int vfs_asroot_lchown(vfs_handle_struct *handle, const char *path, uid_t uid, gid_t gid)
{
	int result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_LCHOWN(handle, path, uid, gid);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static int vfs_asroot_chdir(vfs_handle_struct *handle, const char *path)
{
	int result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_CHDIR(handle, path);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static int vfs_asroot_mknod(vfs_handle_struct *handle, const char *pathname, mode_t mode, SMB_DEV_T dev)
{
        int result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_MKNOD(handle, pathname, mode, dev);

	if (unbecome_root_needed)
		unbecome_root();

        return result;
}

static char *vfs_asroot_realpath(vfs_handle_struct *handle, const char *path)
{
	char *result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_REALPATH(handle, path);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

/* NT ACL operations. */

static NTSTATUS vfs_asroot_fget_nt_acl(vfs_handle_struct *handle,
				       files_struct *fsp,
				       uint32_t security_info,
				       TALLOC_CTX *mem_ctx,
				       struct security_descriptor **ppdesc)
{
	NTSTATUS result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, mem_ctx, ppdesc);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static NTSTATUS vfs_asroot_get_nt_acl(vfs_handle_struct *handle,
				      const char *name,
				      uint32_t security_info,
				      TALLOC_CTX *mem_ctx,
				      struct security_descriptor **ppdesc)
{
	NTSTATUS result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_GET_NT_ACL(handle, name, security_info, mem_ctx, ppdesc);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

#if 0 // set_nt_acl become_root() internally where needed. We don't need to here.
static NTSTATUS vfs_asroot_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp, uint32_t security_info_sent, const struct security_descriptor *psd)
{
	NTSTATUS result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}
#endif

static int vfs_asroot_chmod_acl(vfs_handle_struct *handle, const char *name, mode_t mode)
{
	int result;
	bool unbecome_root_needed = false;

	/*
	 * Permission check is done on current process rather than the opened handle.
	 * Become root to force the operation.
	 */
	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_CHMOD_ACL(handle, name, mode);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static int vfs_asroot_fchmod_acl(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	int result;
	bool unbecome_root_needed = false;

	/*
	 * Permission check is done on current process rather than the opened handle.
	 * Become root to force the operation.
	 */
	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_FCHMOD_ACL(handle, fsp, mode);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
}

static SMB_ACL_T vfs_asroot_sys_acl_get_file(vfs_handle_struct *handle,
					     const char *path_p,
					     SMB_ACL_TYPE_T type,
					     TALLOC_CTX *mem_ctx)
{
/*
 * Since our FUSE client does not support POSIX ACL validation, we won't
 * attempt to fetch POSIX ACL.
 */
#if FUSE_POSIX_ACL_SUPPORT
	SMB_ACL_T result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, path_p, type, mem_ctx);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
#else
	return (SMB_ACL_T)NULL;
#endif
}

static SMB_ACL_T vfs_asroot_sys_acl_blob_get_file(vfs_handle_struct *handle,
						  const char *path_p,
						  TALLOC_CTX *mem_ctx,
						  char **blob_description,
						  DATA_BLOB *blob)
{
/*
 * Since our FUSE client does not support POSIX ACL validation, we won't
 * attempt to fetch POSIX ACL.
 */
#if FUSE_POSIX_ACL_SUPPORT
	SMB_ACL_T result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FILE(handle, path_p, mem_ctx, blob_description, blob);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
#else
	return (SMB_ACL_T)NULL;
#endif
}

static int vfs_asroot_sys_acl_blob_get_fd(vfs_handle_struct *handle,
					  files_struct *fsp,
					  TALLOC_CTX *mem_ctx,
					  char **blob_description,
					  DATA_BLOB *blob)
{
/*
 * Since our FUSE client does not support POSIX ACL validation, we won't
 * attempt to fetch POSIX ACL.
 */
#if FUSE_POSIX_ACL_SUPPORT
	int result;
	bool unbecome_root_needed = false;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	result = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle, fsp, mem_ctx, blob_description, blob);

	if (unbecome_root_needed)
		unbecome_root();

	return result;
#else
	return (-ENOTSUP);
#endif
}

static int vfs_asroot_sys_acl_set_file(vfs_handle_struct *handle, const char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
/*
 * Since our FUSE client does not support POSIX ACL validation, we won't
 * attempt to set POSIX ACL.
 */
#if FUSE_POSIX_ACL_SUPPORT
	bool unbecome_root_needed = false;
	int ret;

	/*
	 * Permission check is done on current process rather than the opened handle.
	 * Become root to force the operation.
	 */
	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	ret = SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, name, acltype, theacl);

	if (unbecome_root_needed)
		unbecome_root();

	return ret;
#else
	return ENOTSUP;
#endif
}

static int vfs_asroot_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp, SMB_ACL_T theacl)
{
/*
 * Since our FUSE client does not support POSIX ACL validation, we won't
 * attempt to set POSIX ACL.
 */
#if FUSE_POSIX_ACL_SUPPORT
	bool unbecome_root_needed = false;
	int ret;

	/*
	 * Permission check is done on current process rather than the opened handle.
	 * Become root to force the operation.
	 */
	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	ret = SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, theacl);

	if (unbecome_root_needed)
		unbecome_root();

	return ret;
#else
	return ENOTSUP;
#endif
}

static int vfs_asroot_sys_acl_delete_def_file(vfs_handle_struct *handle, const char *path)
{
/*
 * Since our FUSE client does not support POSIX ACL validation, we won't
 * attempt to fetch POSIX ACL at all.
 */
#if FUSE_POSIX_ACL_SUPPORT
	bool unbecome_root_needed = false;
	int ret;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	ret = SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle, path);

	if (unbecome_root_needed)
		unbecome_root();

	return ret;
#else
	return ENOTSUP;
#endif
}

/****************************************************************
 Extended attribute operations.
*****************************************************************/

static ssize_t vfs_asroot_getxattr(struct vfs_handle_struct *handle,const char *path, const char *name, void *value, size_t size)
{
	bool unbecome_root_needed = false;
	ssize_t ret;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	ret = SMB_VFS_NEXT_GETXATTR(handle, path, name, value, size);

	if (unbecome_root_needed)
		unbecome_root();

	return ret;
}

static ssize_t vfs_asroot_listxattr(struct vfs_handle_struct *handle, const char *path, char *list, size_t size)
{
	bool unbecome_root_needed = false;
	ssize_t ret;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	ret = SMB_VFS_NEXT_LISTXATTR(handle, path, list, size);

	if (unbecome_root_needed)
		unbecome_root();

	return ret;
}

static int vfs_asroot_removexattr(struct vfs_handle_struct *handle, const char *path, const char *name)
{
	bool unbecome_root_needed = false;
	int ret;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	ret = SMB_VFS_NEXT_REMOVEXATTR(handle, path, name);

	if (unbecome_root_needed)
		unbecome_root();

	return ret;
}

static int vfs_asroot_setxattr(struct vfs_handle_struct *handle, const char *path, const char *name, const void *value, size_t size, int flags)
{
	bool unbecome_root_needed = false;
	int ret;

	BECOME_ROOT_IF_NEEDED(unbecome_root_needed);

	ret = SMB_VFS_NEXT_SETXATTR(handle, path, name, value, size, flags);

	if (unbecome_root_needed)
		unbecome_root();

	return ret;
}

static struct vfs_fn_pointers vfs_asroot_fns = {

	/* Directory operations */
	.opendir_fn = vfs_asroot_opendir,
	.fdopendir_fn = vfs_asroot_fdopendir,
	.rmdir_fn = vfs_asroot_rmdir,

	/* File operations */
	.rename_fn = vfs_asroot_rename,
	.stat_fn = vfs_asroot_stat,
	.fstat_fn = vfs_asroot_fstat,
	.lstat_fn = vfs_asroot_lstat,
	.unlink_fn = vfs_asroot_unlink,
	.chmod_fn = vfs_asroot_chmod,
	.fchmod_fn = vfs_asroot_fchmod,
	.chown_fn = vfs_asroot_chown,
	.fchown_fn = vfs_asroot_fchown,
	.lchown_fn = vfs_asroot_lchown,
	.chdir_fn = vfs_asroot_chdir,
	.mknod_fn = vfs_asroot_mknod,
	.realpath_fn = vfs_asroot_realpath,

	/* NT ACL operations. */

	// The following get_nt_acl functions will fall back to
	// path base. We need to become root to prevent EPERM error
	.fget_nt_acl_fn = vfs_asroot_fget_nt_acl,
	.get_nt_acl_fn = vfs_asroot_get_nt_acl,

	// become_root is done internally so we can omit fset_nt_acl
	//.fset_nt_acl_fn = vfs_asroot_fset_nt_acl,

	/* POSIX ACL operations. */
	.chmod_acl_fn = vfs_asroot_chmod_acl,
	.fchmod_acl_fn = vfs_asroot_fchmod_acl,

	// The following sys_acl_get_* functions will fall back to
	// path base. We need to become root to prevent EPERM error.
	.sys_acl_get_file_fn = vfs_asroot_sys_acl_get_file,
	.sys_acl_blob_get_file_fn = vfs_asroot_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = vfs_asroot_sys_acl_blob_get_fd,

	.sys_acl_set_file_fn = vfs_asroot_sys_acl_set_file,
	.sys_acl_set_fd_fn = vfs_asroot_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = vfs_asroot_sys_acl_delete_def_file,

	/* EA operations. */
	.getxattr_fn = vfs_asroot_getxattr,
	.listxattr_fn = vfs_asroot_listxattr,
	.removexattr_fn = vfs_asroot_removexattr,
	.setxattr_fn = vfs_asroot_setxattr,

};

NTSTATUS vfs_asroot_init(void);
NTSTATUS vfs_asroot_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"asroot", &vfs_asroot_fns);
}



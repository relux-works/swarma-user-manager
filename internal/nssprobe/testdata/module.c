/* Isolated NSS ABI fixture: statuses and public identities only. */
#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <errno.h>
#ifndef PROBE_MODE
#define PROBE_MODE 0
#endif
static int pw,gr,sp;
static char *members[]={"worker-other",0};
enum nss_status _nss_files_setpwent(int stay) {pw=0;return NSS_STATUS_SUCCESS;}
enum nss_status _nss_files_setgrent(int stay) {gr=0;return NSS_STATUS_SUCCESS;}
enum nss_status _nss_files_setspent(int stay) {sp=0;return PROBE_MODE==1?NSS_STATUS_UNAVAIL:NSS_STATUS_SUCCESS;}
enum nss_status _nss_files_endpwent(void) {return NSS_STATUS_SUCCESS;}
enum nss_status _nss_files_endgrent(void) {return NSS_STATUS_SUCCESS;}
enum nss_status _nss_files_endspent(void) {return NSS_STATUS_SUCCESS;}
enum nss_status _nss_files_getpwent_r(struct passwd *p,char *buf,size_t n,int *e) {
 if(PROBE_MODE==4) { for(;;) {} }
 if(pw++) {if(PROBE_MODE==2){*e=EIO;return NSS_STATUS_UNAVAIL;}return NSS_STATUS_NOTFOUND;}
 *p=(struct passwd){.pw_name="worker-fixture",.pw_passwd="x",.pw_uid=24000,.pw_gid=24000,.pw_dir="/opt/swarma/workers/worker-fixture",.pw_shell="/usr/sbin/nologin"};return NSS_STATUS_SUCCESS;
}
enum nss_status _nss_files_getgrent_r(struct group *g,char *buf,size_t n,int *e) {
 if(gr++)return NSS_STATUS_NOTFOUND;
 *g=(struct group){.gr_name="worker-fixture",.gr_passwd="x",.gr_gid=24000,.gr_mem=members};return NSS_STATUS_SUCCESS;
}
enum nss_status _nss_files_getspent_r(struct spwd *s,char *buf,size_t n,int *e) {
 if(sp++) {if(PROBE_MODE==3){*e=ERANGE;return NSS_STATUS_TRYAGAIN;}return NSS_STATUS_NOTFOUND;}
 *s=(struct spwd){.sp_namp="worker-fixture",.sp_pwdp="!FIXTURE-SENTINEL-NEVER-EMIT"};return NSS_STATUS_SUCCESS;
}

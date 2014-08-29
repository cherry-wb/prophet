/*
 * bundle_mechanism.h
 *
 *  Created on: 2014-5-28
 *      Author: wb
 */

#ifndef BUNDLE_MECHANISM_H_
#define BUNDLE_MECHANISM_H_

#ifdef __cplusplus
extern "C"
{
#endif
#ifndef PATH_MAX
#define PATH_MAX        4096	/* # chars in a path name including nul */
#endif
typedef struct _bundle_interface {
  void (*bundle_cleanup)(void);
} bundle_interface_t;
typedef struct BundleInfo {
	void *handle;
	bundle_interface_t *bundle;
	char bundle_path[PATH_MAX];
} BundleInfo;

extern struct BundleInfo dbaf_bundles[];
extern int dbaf_bundles_size;

void s2e_load_bundle(const char *plugin_path);
void s2e_unload_bundle(const char *plugin_path);
void s2e_unload_all_bundle();
#ifdef __cplusplus
}
#endif
#endif /* BUNDLE_MECHANISM_H_ */

#include <sys/time.h>

#include <s2e/bundle_mechanism.h>

static bundle_interface_t publicbundle_interface;

void publicbundle_cleanup_internal(void);
void publicbundle_cleanup(void);
bundle_interface_t* init_bundle(void);

void publicbundle_cleanup(){
	publicbundle_cleanup_internal();
}

bundle_interface_t* init_bundle(void) {
	publicbundle_interface.bundle_cleanup = &publicbundle_cleanup;
	return (&publicbundle_interface);
}


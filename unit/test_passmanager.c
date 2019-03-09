/* Copyright 2019 - oddcoder*/
#include <r_passmanager/passmanager.h>
#include "minunit.h"

bool test_pass_manager_creation (void) {
	FunctionPassManager *fpm = fpm_new ();
	mu_assert_notnull (fpm, "Failed to create Pass Manager");
	fpm_free (fpm);
	mu_end;
}

bool test_pass_manager_anal (void) {
	FunctionPassManager *fpm = fpm_new ();

	RAnal *anal = malloc (sizeof (RAnal));
	fpm_set_anal (fpm, anal);
	mu_assert_ptreq (fpm_get_anal (fpm), anal,
		"Either RAnalFunctionPM_getRAnal or RAnalFunctionPM_setRanal are corrupted");
	free (anal);
	fpm_free (fpm);
	mu_end;
}

void *countBB (FunctionPassManager *pm, FunctionPass *p, RAnalFunction *f) {
	RAnalBlock *bb;
	RListIter *iter;
	int *x = malloc (sizeof (int));
	*x = 0;
	r_list_foreach (f->bbs, iter, bb) {
		(*x)++;
	}
	return x;
}
void *invalidatecb (FunctionPassManager *pm, FunctionPass *p, RAnalFunction *f) {
	free (fpm_get_cached_result (pm, p->name, f));
	return NULL;
}
bool test_pass_manager_new_pass (void) {
	FunctionPassManager *fpm = fpm_new ();
	FunctionPass p;
	p.name = "COUNTBB";
	mu_assert_eq (fpm_register_pass (fpm, &p), false, "Added pass without run or invalidate callbacks");
	p.run = countBB;
	mu_assert_eq (fpm_register_pass (fpm, &p), false, "Added pass without invalidate callback");
	p.run = NULL;
	p.invalidate = invalidatecb;
	mu_assert_eq (fpm_register_pass (fpm, &p), false, "Added pass without run callback");
	p.run = countBB;
	mu_assert_eq (fpm_register_pass (fpm, &p), true, "Failed to add perfectly valid pass");
	fpm_free (fpm);
	mu_end;
}

RAnalFunction *newTestFunction (int bb_count) {
	RAnalFunction *f = r_anal_fcn_new ();
	for (int i = 0; i < bb_count; i++) {
		RAnalBlock *b = r_anal_bb_new ();
		r_anal_fcn_bbadd (f, b);
	}
	return f;
}
bool test_pass_manager_results_fetching (void) {
	FunctionPass countBBPass = {
		.name = "COUNTBB",
		.run = countBB,
		.invalidate = invalidatecb,
	};
	char name[] = "COUNTBB";
	FunctionPassManager *fpm = fpm_new ();
	fpm_register_pass (fpm, &countBBPass);
	RAnalFunction *f = newTestFunction (5);
	int *count = NULL;

	count = fpm_get_cached_result (fpm, name, f);
	mu_assert_null (count, "There is cached result without calculating the real result ever");
	count = fpm_get_result (fpm, name, f);
	mu_assert_notnull (count, "Failed at PM_getResult");
	mu_assert_eq (*count, 5, "PM_getResult returned wrong value");
	mu_assert_ptreq (count, fpm_get_result (fpm, name, f), "PM_getResult didn't cache the value");
	mu_assert_ptreq (count, fpm_get_cached_result (fpm, name, f),
		"PM_getCachedResult couldn't find the cached value");
	fpm_invalidate (fpm, f);
	count = fpm_get_cached_result (fpm, name, f);
	mu_assert_null (count, "There is cached result after NULL invalidation");
	fpm_free (fpm);
	r_anal_fcn_free (f);
	mu_end;
}
void *PASSAResults (FunctionPassManager *pm, FunctionPass *p, RAnalFunction *f) {
	return fpm_get_result (pm, "PASSB", f);
}
void *PASSBResults (FunctionPassManager *pm, FunctionPass *p, RAnalFunction *f) {
	return fpm_get_result (pm, "PASSA", f);
}
void registerPASSADependencies (FunctionPassManager *pm);
void registerPASSBDependencies (FunctionPassManager *pm);
// This is the only recommended way to declare a pass, as a global variable
FunctionPass PASSA = {
	.name = "PASSA",
	.registerDependencies = registerPASSADependencies,
	.run = PASSAResults,
	.invalidate = invalidatecb,
};
FunctionPass PASSB = {
	.name = "PASSB",
	.registerDependencies = registerPASSBDependencies,
	.run = PASSBResults,
	.invalidate = invalidatecb,
};
void registerPASSADependencies (FunctionPassManager *pm) {
	fpm_register_pass (pm, &PASSB);
}
void registerPASSBDependencies (FunctionPassManager *pm) {
	fpm_register_pass (pm, &PASSA);
}

/*
 * We have 2 types of circular dependencies, first one I call it
 * soft circular dependency, and the other is hard circular dependency.
 * For the record, the names are ripoff.
 * The Hard circular dependency is when result(PassA, Object1) would
 * require sequence of other passes as dependencies, one of which would also be
 * result(PassA, Object1), That kind of dependency doesn't need to be direct for example
 * result(PassA, Object1) could require result(PassB, Object1) which in turn requires
 * result(PassA, Object1). This kind of dependency is not tolerated and should fail.
 * Hard circular dependency triggers the radare2 version of asserts.
 * Hard circular dependency checking is done at run time.
 *
 * On the Other hand soft circular dependency is when passA needs to register PassB and
 * passB needs to register PassA. Ideally this should be tolerated, and the The passmanager
 * should be able to resolve the circular dependency in this case. A good use case for this
 * type of dependency is when result(passA, FunctionX) requires result(passB, FunctionY) where
 * functionY is all the functions called by FunctionX except FunctionX itself, but then
 * result(passB, FunctionY) would require result(passA, FunctionY)
 * (assuming no hard circular dependency is triggered).
 */

bool test_circulardependencies () {
	FunctionPassManager *fpm = fpm_new ();
	RAnalFunction *f = newTestFunction (1);

	fpm_register_pass (fpm, &PASSA);
	fpm_get_result (fpm, "PASSA", f); // Not segfaulting or infinity looping is considered passed
	fpm_get_result (fpm, "PASSB", f); // same as above

	fpm_free (fpm);
	r_anal_fcn_free (f);
	mu_end;
}
int main (int argc, char **argv) {
	mu_run_test (test_pass_manager_creation);
	mu_run_test (test_pass_manager_anal);
	mu_run_test (test_pass_manager_new_pass);
	mu_run_test (test_pass_manager_results_fetching);
	mu_run_test (test_circulardependencies);
	return tests_passed != tests_run;
}

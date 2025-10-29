#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#define VALIDATORS 120000000

volatile int scale(double active_sc) {
    return (int)sqrt(active_sc);
}

void loop(double* arr, volatile double* scaled) {
    #pragma omp parallel for
    for (int i = 0; i < VALIDATORS; i++) {
        scaled[i] = (int)sqrt(arr[i]);
    }
}

int main() {
    double* validator_array = NULL;
    volatile double* scaled_array = NULL;

    validator_array = (double*) malloc(VALIDATORS * sizeof(double));
    scaled_array = (double*) malloc(VALIDATORS * sizeof(double));
    srand(time(NULL));
    // Generate random amount of active SC
    // The aSC has to be greater than 10,000 as the
    // assumption is that only validators with at least
    // 10,000 aSC can compete in leader elections
    for (int i = 0; i < VALIDATORS; i++) {
        validator_array[i] = (rand() % 1000000) + 10000;
        //validator_array[i] = rand() % 1000000000;
    }

    struct timespec start, end;
    double cpu_time_used;
    clock_gettime(CLOCK_MONOTONIC, &start);
    loop(validator_array, scaled_array);
    clock_gettime(CLOCK_MONOTONIC, &end);
    cpu_time_used = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("Elapsed time: %f seconds\n", cpu_time_used);
    return 0;
}

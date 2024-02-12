#include <time.h>

#include <stdio.h>

int main() {
    clock_t start_time = clock();

  // code or function to benchmark
  int i = 0;
  for(i;i<655356;i++)
  {
    volatile int x = 0;
  }  

  double elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
  printf("Done in %f seconds\n", elapsed_time);
  return 0;
}

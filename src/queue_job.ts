// vim: ts=4:sw=4:expandtab

/*
 * jobQueue manages multiple queues indexed by device to serialize
 * session io ops on the database.
 */

interface Job<T> {
  awaitable: () => Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: any) => void;
}

const _queueAsyncBuckets = new Map<any, Job<any>[]>();
const _gcLimit = 10000;

async function _asyncQueueExecutor<T>(queue: Job<T>[], cleanup: () => void): Promise<void> {
  let offt = 0;
  while (true) {
      let limit = Math.min(queue.length, _gcLimit); // Break up thundering herds for GC duty.
      for (let i = offt; i < limit; i++) {
          const job = queue[i];
          try {
              job.resolve(await job.awaitable());
          } catch(e) {
              job.reject(e);
          }
      }
      if (limit < queue.length) {
          /* Perform lazy GC of queue for faster iteration. */
          if (limit >= _gcLimit) {
              queue.splice(0, limit);
              offt = 0;
          } else {
              offt = limit;
          }
      } else {
          break;
      }
  }
  cleanup();
}

function jobQueue<T>(bucket: any, awaitable: () => Promise<T>): Promise<T> {
  /* Run the async awaitable only when all other async calls registered
   * here have completed (or thrown).  The bucket argument is a hashable
   * key representing the task queue to use. */
  if (!awaitable.name) {
      // Make debugging easier by adding a name to this function.
      Object.defineProperty(awaitable, 'name', { writable: true });
      if (typeof bucket === 'string') {
          // @ts-ignore - we know it's a string
          awaitable.name = bucket;
      } else {
          console.warn("Unhandled bucket type (for naming):", typeof bucket, bucket);
      }
  }
  let inactive = false;
  if (!_queueAsyncBuckets.has(bucket)) {
      _queueAsyncBuckets.set(bucket, []);
      inactive = true;
  }
  const queue = _queueAsyncBuckets.get(bucket)!;
  const job = new Promise<T>((resolve, reject) => queue.push({
      awaitable,
      resolve,
      reject
  }));
  if (inactive) {
      /* An executor is not currently active; Start one now. */
      _asyncQueueExecutor(queue, () => _queueAsyncBuckets.delete(bucket));
  }
  return job;
}

export default jobQueue;
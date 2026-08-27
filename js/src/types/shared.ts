/** A value that an SDK callback may produce synchronously or asynchronously. */
export type Awaitable<TValue> = TValue | PromiseLike<TValue>;

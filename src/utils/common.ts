export function mapRecord<K extends string | number | symbol, V, U>(
  record: Record<K, V>,
  map: (key: K, value: V) => U,
): Record<K, U> {
  const result: Record<K, U> = {} as Record<K, U>;

  for (const key in record) {
    result[key] = map(key, record[key]);
  }

  return result;
}

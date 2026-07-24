export class LRUCache<K, V> {
  private max: number;
  private map = new Map<K, V>();
  constructor(max: number) { this.max = max; }
  get(key: K): V | undefined {
    if (!this.map.has(key)) return undefined;
    const val = this.map.get(key)!;
    this.map.delete(key);
    this.map.set(key, val);
    return val;
  }
  set(key: K, val: V): void {
    if (this.map.has(key)) this.map.delete(key);
    else if (this.map.size >= this.max) {
      const firstKey = this.map.keys().next().value;
      if (firstKey !== undefined) this.map.delete(firstKey);
    }
    this.map.set(key, val);
  }
  has(key: K): boolean { return this.map.has(key); }
  clear(): void { this.map.clear(); }
}

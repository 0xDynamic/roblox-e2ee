export class ReplayCache {
    private map = new Map<string, number>();

    constructor(private ttlSec = 120) {
        setInterval(() => this.gc(), 30_000).unref?.();
    }

    check(mark: string) {
        if (this.map.has(mark)) return false;
        this.map.set(mark, Math.floor(Date.now() / 1000));
        return true;
    }

    private gc() {
        const now = Math.floor(Date.now() / 1000);
        for (const [k, t] of this.map) {
            if (now - t > this.ttlSec) {
                this.map.delete(k);
            }
        }
    }
}

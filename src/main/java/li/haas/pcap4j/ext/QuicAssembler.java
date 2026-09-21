package li.haas.pcap4j.ext;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Puts a QUIC client hello back together. Browsers now send hellos of two to three kilobytes,
 * mostly post-quantum key shares, so one arrives as several CRYPTO fragments spread over
 * several Initial packets, not always in order. Fragments are collected per connection id
 * until the contiguous run from offset zero parses as a client hello.
 */
public final class QuicAssembler {

    /** A hello larger than this is not worth holding on to. */
    private static final int MAX_BYTES = 64 * 1024;

    private final Map<String, TreeMap<Long, byte[]>> pending = new HashMap<>();

    /**
     * Adds a packet's fragments and returns the client hello once it can be read, else null.
     * The connection id keys the buffer, so parallel connections do not mix.
     */
    public Tls add(Quic quic) {
        final TreeMap<Long, byte[]> parts =
                pending.computeIfAbsent(quic.destinationConnectionId(), k -> new TreeMap<>());
        for (Quic.Fragment f : quic.fragments()) {
            parts.merge(f.offset(), f.data(), (a, b) -> a.length >= b.length ? a : b);
        }

        final byte[] contiguous = contiguousPrefix(parts);
        if (contiguous.length == 0) return null;

        final Tls hello = Tls.parseHandshake(contiguous);
        if (hello != null) {
            pending.remove(quic.destinationConnectionId());   // done with this connection
        } else if (total(parts) > MAX_BYTES) {
            pending.remove(quic.destinationConnectionId());   // give up rather than grow forever
        }
        return hello;
    }

    /** The bytes from offset zero up to the first gap. */
    private static byte[] contiguousPrefix(TreeMap<Long, byte[]> parts) {
        final byte[] first = parts.get(0L);
        if (first == null) return new byte[0];

        byte[] out = first;
        long end = first.length;
        boolean grew = true;
        while (grew) {
            grew = false;
            for (Map.Entry<Long, byte[]> e : parts.entrySet()) {
                final long start = e.getKey();
                final long stop = start + e.getValue().length;
                if (start <= end && stop > end) {
                    final int skip = (int) (end - start);
                    final byte[] merged = new byte[(int) stop];
                    System.arraycopy(out, 0, merged, 0, out.length);
                    System.arraycopy(e.getValue(), skip, merged, (int) end, (int) (stop - end));
                    out = merged;
                    end = stop;
                    grew = true;
                }
            }
        }
        return out;
    }

    private static int total(TreeMap<Long, byte[]> parts) {
        return parts.values().stream().mapToInt(b -> b.length).sum();
    }
}

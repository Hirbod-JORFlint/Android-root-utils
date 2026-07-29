package com.opencode.netstats;

import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ServiceManager;
import java.io.BufferedReader;
import java.io.FileReader;

public class NetworkStatsProxy extends Binder {
    private static final String DESCRIPTOR = "android.net.INetworkStatsService";

    private static final int TX_getIfaceStats  = 12;
    private static final int TX_getTotalStats  = 13;

    private IBinder original;

    public NetworkStatsProxy() {
        attachInterface(null, DESCRIPTOR);
        this.original = ServiceManager.getService("netstats");
        ServiceManager.addService("netstats", this);
    }

    public boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
        if (code == IBinder.INTERFACE_TRANSACTION) {
            reply.writeString(DESCRIPTOR);
            return true;
        }
        if (code == TX_getIfaceStats) {
            return onGetIfaceStats(data, reply);
        }
        if (code == TX_getTotalStats) {
            return onGetTotalStats(data, reply);
        }
        return pass(code, data, reply, flags);
    }

    private boolean onGetIfaceStats(Parcel data, Parcel reply) {
        data.enforceInterface(DESCRIPTOR);
        String iface = data.readString();
        data.enforceNoDataAvail();

        long[] s = readIface(iface);

        reply.writeNoException();
        writeResult(reply, s[0], s[1], s[2], s[3]);
        return true;
    }

    private boolean onGetTotalStats(Parcel data, Parcel reply) {
        data.enforceInterface(DESCRIPTOR);
        data.enforceNoDataAvail();

        long[] s = readAllNonLo();

        reply.writeNoException();
        writeResult(reply, s[0], s[1], s[2], s[3]);
        return true;
    }

    private long[] readIface(String iface) {
        long[] r = new long[]{0, 0, 0, 0};
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/net/dev"));
            String line;
            while ((line = br.readLine()) != null) {
                String t = line.trim();
                if (t.startsWith(iface + ":")) {
                    String[] p = t.split("\\s+");
                    if (p.length >= 11) {
                        r[0] = Long.parseLong(p[1]);  // rxBytes
                        r[1] = Long.parseLong(p[2]);  // rxPackets
                        r[2] = Long.parseLong(p[9]);  // txBytes
                        r[3] = Long.parseLong(p[10]); // txPackets
                    }
                    break;
                }
            }
            br.close();
        } catch (Exception ignored) {}
        return r;
    }

    private long[] readAllNonLo() {
        long[] r = new long[]{0, 0, 0, 0};
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/net/dev"));
            br.readLine();
            br.readLine();
            String line;
            while ((line = br.readLine()) != null) {
                String t = line.trim();
                if (t.startsWith("lo:")) continue;
                String[] p = t.split("\\s+");
                if (p.length >= 11) {
                    r[0] += Long.parseLong(p[1]);
                    r[1] += Long.parseLong(p[2]);
                    r[2] += Long.parseLong(p[9]);
                    r[3] += Long.parseLong(p[10]);
                }
            }
            br.close();
        } catch (Exception ignored) {}
        return r;
    }

    private void writeResult(Parcel reply, long rxBytes, long rxPackets, long txBytes, long txPackets) {
        int start = reply.dataPosition();
        reply.writeInt(0);
        reply.writeLong(rxBytes);
        reply.writeLong(rxPackets);
        reply.writeLong(txBytes);
        reply.writeLong(txPackets);
        int end = reply.dataPosition();
        int size = end - start;
        reply.setDataPosition(start);
        reply.writeInt(size);
        reply.setDataPosition(end);
    }

    private boolean pass(int code, Parcel data, Parcel reply, int flags) {
        if (original != null) {
            try {
                return original.transact(code, data, reply, flags);
            } catch (Exception e) {
                log("pass error: " + e);
            }
        }
        return false;
    }

    private static void log(String m) {
        System.out.println("NetProxy: " + m);
    }

    private void monitor() {
        log("monitor started");
        while (true) {
            try {
                Thread.sleep(10000);
                IBinder current = ServiceManager.getService("netstats");
                if (current != this) {
                    log("re-registering (current=" + current + ")");
                    original = current;
                    ServiceManager.addService("netstats", this);
                    log("re-register OK");
                }
            } catch (Exception e) {
                log("monitor error: " + e);
            }
        }
    }

    public static void main(String[] args) {
        try {
            Thread.sleep(5000);

            IBinder svc = ServiceManager.getService("netstats");
            if (svc == null) {
                log("netstats service not found");
                return;
            }

            NetworkStatsProxy p = new NetworkStatsProxy();
            log("registered. original=" + (p.original != null));

            IBinder check = ServiceManager.getService("netstats");
            log("self-check: " + (check == p ? "PASS" : "FAIL"));

            p.monitor();
        } catch (Exception e) {
            log("fatal: " + e);
        }
    }
}

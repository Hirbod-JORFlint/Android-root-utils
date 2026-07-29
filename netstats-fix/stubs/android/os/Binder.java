package android.os;

import java.io.FileDescriptor;

public class Binder implements IBinder {
    private IInterface mOwner;
    private String mDescriptor;

    public Binder() { mOwner = null; mDescriptor = null; }

    public void attachInterface(IInterface owner, String descriptor) {
        mOwner = owner; mDescriptor = descriptor;
    }

    public String getInterfaceDescriptor() { return mDescriptor; }
    public boolean pingBinder() { return true; }
    public boolean isBinderAlive() { return true; }

    public IInterface queryLocalInterface(String descriptor) {
        if (mDescriptor != null && mDescriptor.equals(descriptor)) return mOwner;
        return null;
    }

    public void dump(FileDescriptor fd, String[] args) {}
    public void dumpAsync(FileDescriptor fd, String[] args) {}

    protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
        if (code == INTERFACE_TRANSACTION) { reply.writeString(getInterfaceDescriptor()); return true; }
        return false;
    }

    public boolean transact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
        return onTransact(code, data, reply, flags);
    }

    public boolean linkToDeath(DeathRecipient recipient, int flags) { return true; }
    public boolean unlinkToDeath(DeathRecipient recipient, int flags) { return true; }
    public static long clearCallingIdentity() { return 0; }
    public static void restoreCallingIdentity(long token) {}
    public static int getCallingPid() { return 0; }
    public static int getCallingUid() { return 0; }
}

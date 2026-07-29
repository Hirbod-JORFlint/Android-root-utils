package android.os;

import java.io.FileDescriptor;

public interface IBinder {
    int FIRST_CALL_TRANSACTION = 1;
    int LAST_CALL_TRANSACTION = 0x00ffffff;
    int DUMP_TRANSACTION = 0x5f444d50;
    int LIKE_TRANSACTION = 0x4c494b45;
    int SYSPROPS_TRANSACTION = 0x53595350;
    int TWEET_TRANSACTION = 0x54574554;
    int PING_TRANSACTION = 0x504e4700;
    int INTERFACE_TRANSACTION = 0x5f4e5446;
    int FLAG_ONEWAY = 0x00000001;
    int FLAG_CLEAR_BUF = 0x00000002;

    String getInterfaceDescriptor() throws RemoteException;
    boolean pingBinder();
    boolean isBinderAlive();
    IInterface queryLocalInterface(String descriptor);
    void dump(FileDescriptor fd, String[] args) throws RemoteException;
    void dumpAsync(FileDescriptor fd, String[] args) throws RemoteException;
    boolean transact(int code, Parcel data, Parcel reply, int flags) throws RemoteException;
    boolean linkToDeath(DeathRecipient recipient, int flags);
    boolean unlinkToDeath(DeathRecipient recipient, int flags);

    interface DeathRecipient {
        void binderDied();
    }
}

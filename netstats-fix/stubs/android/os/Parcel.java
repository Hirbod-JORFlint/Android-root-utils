package android.os;

public class Parcel {
    Parcel() {}

    public static Parcel obtain() { return new Parcel(); }
    public void recycle() {}

    public int dataPosition() { return 0; }
    public void setDataPosition(int pos) {}

    public void writeInt(int val) {}
    public void writeLong(long val) {}
    public void writeString(String val) {}
    public void writeInterfaceToken(String token) {}
    public void writeNoException() {}
    public void writeStrongBinder(IBinder val) {}
    public void writeStrongInterface(IInterface val) {}
    public void writeTypedObject(Parcelable val, int flags) {}
    public void writeByteArray(byte[] val) {}
    public void writeBoolean(boolean val) {}

    public int readInt() { return 0; }
    public long readLong() { return 0; }
    public String readString() { return null; }
    public String readInterfaceToken() { return null; }
    public void readException() {}
    public IBinder readStrongBinder() { return null; }
    public <T extends Parcelable> T readTypedObject(Parcelable.Creator<T> c) { return null; }
    public byte[] readByteArray() { return null; }
    public boolean readBoolean() { return false; }
    public void enforceInterface(String descriptor) {}
    public void enforceNoDataAvail() {}
}

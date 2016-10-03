package sign4j;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;

public class Sign4j
{
    private static final int END_HEADER_SIZE = 22;
    private static final int MAX_COMMENT_SIZE = 0xFFFF;
    private static final int SWAP_BLOCK_SIZE = 4 * 1024 * 1024;

    private final File exeFile;
    private final File tempFile = new File("sign4j_temporary.exe");
    private final Signer signer;

    public Sign4j(final File exeFile,
                  final Signer signer)
    {
        this.exeFile = exeFile;
        this.signer = signer;
    }

    public void sign() throws Exception
    {
        final int origExeFileLen = (int) exeFile.length();

        final int blockSize = (origExeFileLen > SWAP_BLOCK_SIZE ? SWAP_BLOCK_SIZE : origExeFileLen);

        final byte[] bytes = new byte[blockSize];

        final int sgm = blockSize > END_HEADER_SIZE + MAX_COMMENT_SIZE ? END_HEADER_SIZE + MAX_COMMENT_SIZE : blockSize;

        readBytes(origExeFileLen, bytes, sgm);

        int pos;

        for (pos = sgm - END_HEADER_SIZE; pos > 0; pos--)
        {
            if (isZipEndHeader(bytes, pos) &&
                getCmn(bytes, pos) == sgm - (pos + END_HEADER_SIZE))
            {
                break;
            }
        }

        if (pos > 0)
        {
            copyToTempFile(exeFile, tempFile);

            signer.sign(tempFile);

            final int tempFileLen = (int) tempFile.length();
            final int cmn = getCmn(bytes, pos) + tempFileLen - origExeFileLen;

            if (cmn < 0 || cmn > MAX_COMMENT_SIZE)
            {
                throw new Exception("unsupported operation");
            }

            final int cmnOffset = origExeFileLen - (sgm - (pos + END_HEADER_SIZE - 2));

            writeCmn(cmn, cmnOffset);
        }
        else
        {
            log("You don't need sign4j to sign this file: " + exeFile);
        }

        signer.sign(exeFile);
    }

    private void writeCmn(final int cmn,
                          final int cmnOffset) throws Exception
    {
        RandomAccessFile file = null;

        try
        {
            file = new RandomAccessFile(exeFile, "rw");

            file.seek(cmnOffset);

            final byte[] bfr = new byte[2];
            bfr[0] = (byte) (cmn & 0xFF);
            bfr[1] = (byte) (cmn >> 8 & 0xFF);

            file.write(bfr);
        }
        finally
        {
            close(file);
        }
    }

    private void readBytes(final int origExeFileLen,
                           final byte[] bytes,
                           final int sgm) throws Exception
    {
        RandomAccessFile file = null;

        try
        {
            file = new RandomAccessFile(exeFile, "r");
            file.seek(origExeFileLen - sgm);
            file.readFully(bytes, 0, sgm);
        }
        finally
        {
            close(file);
        }
    }

    private int getCmn(final byte[] bytes,
                       final int pos)
    {
        return toUnsignedInt(bytes[pos + END_HEADER_SIZE - 1]) << 8 |
               toUnsignedInt(bytes[pos + END_HEADER_SIZE - 2]);
    }

    static boolean isZipEndHeader(final byte[] bytes,
                                  final int offset)
    {
        boolean ret = false;

        final byte[] zipEndHeader = new byte[] {80, 75, 5, 6};

        for (int i = 0; i < zipEndHeader.length; i++)
        {
            ret = bytes[offset + i] == zipEndHeader[i];

            if (!ret)
            {
                break;
            }
        }

        return ret;
    }

    static void copyToTempFile(final File source,
                               final File dest) throws Exception
    {
        log("Creating temporary file");

        dest.delete();
        dest.createNewFile();
        dest.deleteOnExit();

        InputStream is = null;
        OutputStream os = null;
        try
        {
            is = new FileInputStream(source);
            os = new FileOutputStream(dest);

            final byte[] buffer = new byte[1024];

            int length;

            while ((length = is.read(buffer)) > 0)
            {
                os.write(buffer, 0, length);
            }
        }
        finally
        {
            close(is);
            close(os);
        }
    }

    static void close(final Closeable c)
    {
        if (c != null)
        {
            try
            {
                c.close();
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
    }

    static int toUnsignedInt(final byte x)
    {
        return ((int) x) & 0xff;
    }

    static void log(final String s)
    {
        System.out.println(s);
    }
}

package sign4j;

import java.io.Closeable;
import java.io.File;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

public class Sign4j
{
    private static final byte[] ZIP_END_HEADER = new byte[] { 80, 75, 5, 6 };
    private static final int END_HEADER_SIZE = 22;
    private static final int MAX_COMMENT_SIZE = 0xFFFF;
    private static final int SWAP_BLOCK_SIZE = 4 * 1024 * 1024;
    private static final String TEST_FILE_NAME = "sign4j_temporary.exe";
    private static final String SIGN4J_VERSION = "3.0";

    public Sign4j()
    {
    }

    // int main (int argc, char* argv[])
    public static void main(final String[] args) throws Exception
    {
        String inf = null;
        String outf = null;
        int ext;
        int sgm;
        boolean fnd = false;
        boolean spt = false;
        boolean unq = false;
        boolean vrb = false;
        int cmn = 0;
        int i, j;
        int p;

        for (i = 0; i < args.length && args[i].startsWith("-"); i++)
        {
            if ("--onthespot".equals(args[i]))
            {
                spt = true;
            }
            else if ("--strict".equals(args[i]))
            {
                unq = true;
            }
            else if ("--verbose".equals(args[i]))
            {
                vrb = true;
            }
        }

        j = i;
        for (i = j + 1; i < args.length; i++)
        {
            if ("-in".equals(args[i]) && i < args.length - 1)
            {
                inf = args[++i];
                fnd = true;
            }
            else if ("-out".equals(args[i]) && i < args.length - 1)
            {
                outf = args[++i];
                fnd = true;
            }
            else if (args[i].startsWith("-") || (args[i].startsWith("/") && args[i].length() < 5))
            {
                if (!fnd)
                {
                    inf = outf = null;
                }
            }
            else if (!fnd && args[i].endsWith(".exe"))
            {
                inf = outf = args[i];
            }
        }

        if (inf == null || outf == null)
        {
            usage();
        }
        // atexit (clear);

        RandomAccessFile fd = null;
        RandomAccessFile td = null;

        try
        {
            fd = new RandomAccessFile(inf, "r");
        }
        catch (Exception e)
        {
            quit(1);
        }

        final int lng = (int) fd.length();
        fd.seek(fd.length());
        if (lng <= 0)
        {
            quit(2);
        }

        final int blck = (lng > SWAP_BLOCK_SIZE ? SWAP_BLOCK_SIZE : lng);

        final byte[] image = new byte[blck];

        sgm = (blck > END_HEADER_SIZE + MAX_COMMENT_SIZE ? END_HEADER_SIZE + MAX_COMMENT_SIZE : blck);

        fd.seek(lng - sgm);
        fd.readFully(image, 0, sgm);

        for (p = sgm - END_HEADER_SIZE; p > 0; p--)
        {
            final boolean isMatch = image[p + 0] == ZIP_END_HEADER[0] && image[p + 1] == ZIP_END_HEADER[1]
                    && image[p + 2] == ZIP_END_HEADER[2] && image[p + 3] == ZIP_END_HEADER[3];

            if (isMatch && (toUnsignedInt(image[p + END_HEADER_SIZE - 1]) << 8
                    | toUnsignedInt(image[p + END_HEADER_SIZE - 2])) == sgm - (p + END_HEADER_SIZE))
            {
                break;
            }
        }

        if (p > 0)
        {
            final int off = lng - (sgm - (p + END_HEADER_SIZE - 2));
            cmn = toUnsignedInt(image[p + END_HEADER_SIZE - 1]) << 8
                    | toUnsignedInt(image[p + END_HEADER_SIZE - 2]);

            final String trg;
            if (!spt && inf.equals(outf))
            {
                printf("Making temporary file\n");

                new File(TEST_FILE_NAME).delete();
                new File(TEST_FILE_NAME).createNewFile();
                new File(TEST_FILE_NAME).deleteOnExit();
                td = new RandomAccessFile(TEST_FILE_NAME, "rw");

                fd.seek(0);
                for (ext = lng; ext > 0; ext -= blck)
                {
                    sgm = ext > blck ? blck : ext;
                    fd.readFully(image, 0, sgm);
                    td.write(image, 0, sgm);
                }
                close(td);
                trg = TEST_FILE_NAME;
            }
            else
            {
                trg = outf;
            }
            close(fd);

            final List<String> command = new ArrayList<String>();
            for (i = j; i < args.length; i++)
            {
                final String pp = (args[i] == outf ? trg : args[i]);
                command.add(pp.trim());
            }
            system(command);

            td = new RandomAccessFile(trg, "r");
            td.seek(td.length());
            ext = (int) td.length();
            close(td);

            if ((cmn += ext - lng) < 0 || cmn > MAX_COMMENT_SIZE)
            {
                quit(8);
            }

            fd = new RandomAccessFile(inf, "rw");
            fd.seek(off);

            final byte[] bfr = new byte[] { (byte) (cmn & 0xFF), (byte) (cmn >> 8 & 0xFF) };

            fd.write(bfr);

            close(fd);
        }
        else
        {
            close(fd);
            printf("You don't need sign4j to sign this file\n");
        }

        final List<String> command = new ArrayList<String>();
        for (i = j; i < args.length; i++)
        {
            String pp = args[i].trim();
            command.add(pp.trim());
        }

        System.exit(system(command));
    }

    private static void close(Closeable c) throws Exception
    {
        if (c != null)
        {
            c.close();
        }
    }

    private static int system(final List<String> command) throws Exception
    {
        System.out.println("run command: " + command);

        final ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        final Process p = pb.start();
        return p.waitFor();
    }

    private static int toUnsignedInt(byte x) {
        return ((int) x) & 0xff;
    }

    private static void usage()
    {
        printf("\nThis is sign4j version " + SIGN4J_VERSION + "\n\n");
        printf("Usage: sign4j [options] <arguments>\n\n");
        printf(" * options:\n");
        printf("    --onthespot   avoid the creation of a temporary file (your tool must be able to sign twice)\n");
        printf("    --strict      supress the use of double quotes around parameters that strictly don't need them\n");
        printf("    --verbose     show diagnostics about intermediary steps of the process\n");
        printf(" * arguments must specify verbatim the command line for your signing tool\n");
        printf(" * only one file can be signed on each invocation\n");
        System.exit(-1);
    }

    private static void quit(int rsn)
    {
        switch (rsn)
        {
        case 1:
            printf("Could not open file\n");
            break;
        case 2:
            printf("Could not read file\n");
            break;
        case 3:
            printf("Could not write file\n");
            break;
        case 4:
            printf("Not enough memory\n");
            break;
        case 5:
            printf("Could not open temporary\n");
            break;
        case 6:
            printf("Could not write temporary\n");
            break;
        case 7:
            printf("Could not read target\n");
            break;
        case 8:
            printf("Unsupported operation\n");
            break;
        }
        System.exit(-1);
    }

    private static void printf(String s)
    {
        System.out.println(s);
    }

    private static void clear()
    {
        new File(TEST_FILE_NAME).delete();
    }
}

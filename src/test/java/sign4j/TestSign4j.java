package sign4j;

import static org.junit.Assert.*;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import net.jsign.PESignerCLI;
import net.jsign.bouncycastle.cms.CMSSignedData;
import net.jsign.pe.PEFile;

public class TestSign4j
{
    private static final File SOURCE_DIR = new File("src/test/resources/");
    private static final File TARGET_DIR = new File("build/resources/test/");

    private final File keystore = new File("src/test/resources/keystore.jks");
    private final String alias = "selfsigned";
    private final String keypass = "password";

    @Test
    public void testSigning1() throws Exception
    {
        testSigning("wineyes", 2795725784L);
        testSigning("launch4j-test-256b", 621558228L);
        testSigning("launch4j-test-1k", 4009771916L);
        testSigning("launch4j-test-1m", 1330159520L);
        testSigning("launch4j-test-5m", 3008858718L);
    }

    private void testSigning(final String baseFilename,
                             final long sourceFileChecksum) throws Exception
    {
        final File sourceFile = new File(SOURCE_DIR, baseFilename + ".exe");
        final File targetFile = new File(TARGET_DIR, baseFilename + "-signed.exe");

        if (targetFile.exists())
        {
            assertTrue("Unable to remove the previously signed file", targetFile.delete());
        }

        assertEquals("Source file CRC32", sourceFileChecksum, FileUtils.checksumCRC32(sourceFile));
        FileUtils.copyFile(sourceFile, targetFile);

        final Signer signer = new Signer()
        {
            @Override
            public void sign(final File file) throws Exception
            {
                PESignerCLI.main("--keystore=" + keystore.getAbsolutePath(),
                                 "--alias=" + alias,
                                 "--keypass=" + keypass,
                                 file.getAbsolutePath());
            }
        };

        final Sign4j sign4j = new Sign4j(targetFile, signer);
        sign4j.sign();

        assertTrue("The file " + targetFile + " wasn't changed", sourceFileChecksum != FileUtils.checksumCRC32(targetFile));

        PEFile peFile = null;
        try
        {
            peFile = new PEFile(targetFile);

            final List<CMSSignedData> signatures = peFile.getSignatures();
            assertNotNull(signatures);
            assertEquals(1, signatures.size());

            final CMSSignedData signature = signatures.get(0);

            assertNotNull(signature);
        }
        finally
        {
            if (peFile != null)
            {
                peFile.close();
            }
        }
    }

    @Test
    public void testCloseNull() throws Exception
    {
        Sign4j.close(null);
    }

    @Test
    public void testCloseEx() throws Exception
    {
        final Closeable c = new Closeable()
        {
            @Override
            public void close() throws IOException
            {
                throw new IOException();
            }
        };

        Sign4j.close(c);
    }
}

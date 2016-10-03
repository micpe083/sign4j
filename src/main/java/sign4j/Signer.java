package sign4j;

import java.io.File;

public interface Signer
{
    void sign(File file) throws Exception;
}

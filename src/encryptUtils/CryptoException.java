/**
 * Created by Madeline on 11/01/2017.
 */

package encryptUtils;

public class CryptoException extends Exception{

    public CryptoException() {
    }

    /**
     *
     * @param message
     * @param throwable
     */
    public CryptoException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
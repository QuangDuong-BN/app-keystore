package com.example.testapp;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Build;
import android.os.Bundle;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

public class MainActivity extends AppCompatActivity {

    private EditText etUsername;
    private EditText etPassword;
    private Button btnLogin;

    private static final String KEY_ALIAS = "MyKeyAlias";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etUsername = findViewById(R.id.etUsername);
        etPassword = findViewById(R.id.etPassword);
        btnLogin = findViewById(R.id.btnLogin);

        btnLogin.setOnClickListener(new View.OnClickListener() {
            @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
            @Override
            public void onClick(View v) {
                String username = etUsername.getText().toString().trim();
                String password = etPassword.getText().toString().trim();

                if (username.isEmpty() || password.isEmpty()) {
                    Toast.makeText(MainActivity.this, "Please enter username and password", Toast.LENGTH_SHORT).show();
                } else {
                    try {
                        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                        keyStore.load(null);

                        if (!keyStore.containsAlias(KEY_ALIAS)) {
                            Calendar start = Calendar.getInstance();
                            Calendar end = Calendar.getInstance();
                            end.add(Calendar.YEAR, 10);

                            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(MainActivity.this)
                                    .setAlias(KEY_ALIAS)
                                    .setSubject(new X500Principal("CN=" + KEY_ALIAS))
                                    .setSerialNumber(BigInteger.ONE)
                                    .setStartDate(start.getTime())
                                    .setEndDate(end.getTime())
                                    .build();

                            KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
                            generator.initialize(spec);

                            generator.generateKeyPair();
                        }

                        PublicKey publicKey = keyStore.getCertificate(KEY_ALIAS).getPublicKey();
                        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);

                        // mã hóa
                        byte[] encryptedUsername = encrypt(publicKey, username.getBytes());
                        byte[] encryptedPassword = encrypt(publicKey, password.getBytes());

                        // giải mã
                        byte[] decryptedUsername = decrypt(privateKey, encryptedUsername);
                        byte[] decryptedPassword = decrypt(privateKey, encryptedPassword);


                        String encodedEncryptedUsername = Base64.encodeToString(encryptedUsername, Base64.DEFAULT);
                        String encodedEncryptedPassword = Base64.encodeToString(encryptedPassword, Base64.DEFAULT);

                        String encodedUsername = new String(decryptedUsername, StandardCharsets.UTF_8);
                        String encodedPassword = new String(decryptedPassword, StandardCharsets.UTF_8);



                        Toast.makeText(MainActivity.this, "Username: " + encodedEncryptedUsername, Toast.LENGTH_SHORT).show();
                        Toast.makeText(MainActivity.this, "Password: " + encodedEncryptedPassword, Toast.LENGTH_SHORT).show();

                        Toast.makeText(MainActivity.this, "Username: " + encodedUsername, Toast.LENGTH_SHORT).show();
                        Toast.makeText(MainActivity.this, "Password: " + encodedPassword, Toast.LENGTH_SHORT).show();

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        });
    }

    private static byte[] encrypt(PublicKey publicKey, byte[] inputData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(inputData);
    }

    private static byte[] decrypt(PrivateKey privateKey, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

}
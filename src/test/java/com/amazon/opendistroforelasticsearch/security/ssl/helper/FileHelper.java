package com.amazon.opendistroforelasticsearch.security.ssl.helper;

import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.LogManager;
import java.util.logging.Logger;

public class FileHelper {

    public static Path getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
        File file = null;
        final URL fileUrl = FileHelper.class.getClassLoader().getResource(fileNameFromClasspath);
        if (fileUrl != null) {
            try {
                file = new File(URLDecoder.decode(fileUrl.getFile(), "UTF-8"));
            } catch (final UnsupportedEncodingException e) {
                return null;
            }

            if (file.exists() && file.canRead()) {
                return Paths.get(file.getAbsolutePath());
            } else {
                System.out.println("Cannot read from" + file.getAbsolutePath() + ", maybe the file does not exists?" );
            }

        } else {
            System.out.println("Failed to load " + fileNameFromClasspath);
        }
        return null;
    }

    /**
     * Utility that copies contents of one file to another
     * @param srcFile    Source File
     * @param destFile   Destination File
     */
    public static void copyFileContents(String srcFile, String destFile) {
        try {
            final FileReader fr = new FileReader(srcFile);
            final BufferedReader br = new BufferedReader(fr);
            final FileWriter fw = new FileWriter(destFile, false);
            String s;

            while ((s = br.readLine()) != null) { // read a line
                fw.write(s); // write to output file
                fw.write(System.getProperty("line.separator"));
                fw.flush();
            }

            br.close();
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

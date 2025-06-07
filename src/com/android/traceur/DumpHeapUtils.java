/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.android.traceur;

import android.app.ActivityManager;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.os.RemoteCallback;
import android.os.RemoteException;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Paths;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

/**
 * Functions for calling AM's heap dump with bitmaps.
 */
public class DumpHeapUtils {

    static final String TAG = "Traceur";

    private static final String TRACE_DIRECTORY = "/data/local/traces";
    private static final String DATE_FORMAT = "yyyy-MM-dd-HH-mm-ss";

    private static final String TEMP_HPROF_NAME = ".heapdump.in-progress";
    private static final String COMPLETED_HPROF_NAME = "dump-%s.hprof";

    private static final String BITMAP_CLASSNAME = "android.graphics.Bitmap";
    private static final String DUMPDATA_CLASSNAME = "android.graphics.Bitmap$DumpData";

    public static boolean dumpHeapWithAM(Context context, String process) {
        try {
            String date = new SimpleDateFormat(DATE_FORMAT, Locale.US).format(new Date());
            File outputDirectory = new File(getOutputDirectory(date));
            outputDirectory.mkdir();
            File file = new File(outputDirectory, TEMP_HPROF_NAME);
            file.createNewFile();

            final CountDownLatch latch = new CountDownLatch(1);
            final RemoteCallback finishCallback = new RemoteCallback(
                    new RemoteCallback.OnResultListener() {
                        @Override
                        public void onResult(Bundle result) {
                            Log.i(TAG, "dumpHeap() complete");
                            latch.countDown();
                        }
                    }, null);

            Log.i(TAG, "Starting AM dumpHeap()");
            ActivityManager am = context.getSystemService(ActivityManager.class);
            am.getService().dumpHeap(process, /* userId = */ context.getUserId(),
                    /* managed = */ true, /* mallocInfo = */ false, /* runGc = */ false,
                    /* dumpBitmaps = */ "png", /* path = */ file.toString(),
                    /* fd = */ ParcelFileDescriptor.open(file,
                        ParcelFileDescriptor.MODE_READ_WRITE),
                    /* finishCallback = */ finishCallback);
            latch.await();

            File completedHeapDump = new File(outputDirectory,
                    String.format(COMPLETED_HPROF_NAME, date));
            Os.rename(file.getCanonicalPath(), completedHeapDump.getCanonicalPath());

            parseHprofForBitmaps(completedHeapDump);
        } catch (IOException | RemoteException | InterruptedException | ErrnoException e) {
            Log.e(TAG, e.toString());
        }
        return true;
    }

    // Scans through the input hprof file and outputs bitmap images as .pngs in
    // /data/local/traces/<hprof subdirectory>.
    private static void parseHprofForBitmaps(File file) throws IOException {
        FileChannel channel = FileChannel.open(file.toPath(), StandardOpenOption.READ);
        ByteBuffer byteBuffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());
        channel.close();

        StringBuilder format = new StringBuilder();
        HprofBuffer buf = new HprofBuffer(byteBuffer);

        int b;
        while ((b = buf.getU1()) != 0) {
            format.append((char)b);
        }

        int idSize = buf.getU4();
        boolean idSize8 = false;
        if (idSize == 8) {
            idSize8 = true;
        } else if (idSize != 4) {
            Log.e(TAG, "Id size " + idSize + " not supported.");
            return;
        }

        int hightime = buf.getU4();
        int lowtime = buf.getU4();

        // Map of string IDs to Strings.
        Map<Long, String> strings = new HashMap<>();

        // Map of class object IDs to class name string IDs.
        Map<Long, Long> classes = new HashMap<>();

        // android.graphics.Bitmap instance fields.
        List<Field> bitmapFields = new ArrayList<>();

        // android.graphics.Bitmap$DumpData instance fields.
        List<Field> dumpDataFields = new ArrayList<>();

        int startPosition = buf.position();

        // In the first pass through the heap dump, we record strings, class names, and class dumps.
        while (buf.hasRemaining()) {
            int tag = buf.getU1();
            int time = buf.getU4();
            int recordLength = buf.getU4();
            if (tag == 0x01) { // STRING
                long id = buf.getId(idSize8);
                byte[] bytes = new byte[recordLength - idSize];
                buf.getBytes(bytes);

                String string = new String(bytes, StandardCharsets.UTF_8);
                if (isRelevantString(string)) {
                    strings.put(id, string);
                }
            } else if (tag == 0x02) { // LOAD CLASS
                int classSerialNumber = buf.getU4();
                long objectId = buf.getId(idSize8);
                int stackSerialNumber = buf.getU4();
                long classNameStringId = buf.getId(idSize8);

                if (isRelevantString(strings.get(classNameStringId))) {
                    classes.put(objectId, classNameStringId);
                }
            } else if (tag == 0x0C || tag == 0x1C) {
                int endOfRecord = buf.position() + recordLength;
                while (buf.position() < endOfRecord) {
                    int subtag = buf.getU1();
                    if (handleIrrelevantSubtags(subtag, buf, idSize8, idSize)) {
                        // Nothing to do here.
                    } else if (handlePossiblyRelevantSubtags(subtag, buf, idSize8, idSize,
                            /* firstPass = */ true)) {
                        // Nothing to do here.
                    } else if (subtag == 0x20) { // CLASS DUMP
                        long objectId = buf.getId(idSize8);
                        int stackSerialNumber = buf.getU4();
                        long superClassId = buf.getId(idSize8);
                        long classLoaderId = buf.getId(idSize8);
                        long signersId = buf.getId(idSize8);
                        long protectionId = buf.getId(idSize8);
                        long reserved1 = buf.getId(idSize8);
                        long reserved2 = buf.getId(idSize8);
                        int instanceSize = buf.getU4();

                        int constantPoolSize = buf.getU2();
                        for (int i = 0; i < constantPoolSize; i++) {
                            int index = buf.getU2();
                            Type type = buf.getType();
                            buf.skip(type.size(idSize));
                        }

                        int numStaticFields = buf.getU2();
                        for (int i = 0; i < numStaticFields; i++) {
                            long nameId = buf.getId(idSize8);
                            Type type = buf.getType();
                            buf.skip(type.size(idSize));
                        }

                        String className = strings.get(classes.get(objectId));
                        boolean isBitmapClass = BITMAP_CLASSNAME.equals(className);
                        boolean isDumpDataClass = DUMPDATA_CLASSNAME.equals(className);

                        int numInstanceFields = buf.getU2();
                        for (int i = 0; i < numInstanceFields; i++) {
                            long nameId = buf.getId(idSize8);
                            Type type = buf.getType();
                            if (isBitmapClass) {
                                bitmapFields.add(new Field(strings.get(nameId), type));
                            } else if (isDumpDataClass) {
                                dumpDataFields.add(new Field(strings.get(nameId), type));
                            }
                        }
                    } else {
                        Log.e(TAG, String.format("subtag %x not found", subtag));
                    }
                }
            } else {
                buf.skip(recordLength);
            }
        }

        if (bitmapFields.isEmpty()) {
            Log.e(TAG, "Never found Bitmap class dump.");
        }
        if (dumpDataFields.isEmpty()) {
            Log.e(TAG, "Never found DumpData class dump.");
        }

        // ID of the android.graphics.Bitmap$DumpData's 'buffers' field. This points to an array of
        // IDs, each of which represents a byte[] (that a Bitmap object can be produced from).
        long dumpDataBuffersId = -1;
        List<Long> bitmapBufferRefs = new ArrayList<>();
        Map<Long, byte[]> bitmapBuffers = new HashMap<>();

        // ID of the android.graphics.Bitmap$DumpData's 'natives' field. This points to an array of
        // longs, each of which uniquely identifies a bitmap.
        long dumpDataNativesId = -1;
        List<Long> nativePtrs = new ArrayList<>();

        // ID of the android.graphics.Bitmap$DumpData's 'sizes' field. This points to an array of
        // longs, each of which holds a Bitmap object's size (as calculated by
        // Bitmap.getAllocationByteCount()).
        long dumpDataSizesId = -1;
        List<Integer> sizes = new ArrayList<>();

        // Map of nativePtrs to bitmap dimensions.
        Map<Long, Dimensions> dimensions = new HashMap<>();

        // In the second pass through the heap dump, we record Bitmap/DumpData instances and their
        // fields that we care about.
        buf.seek(startPosition);
        while (buf.hasRemaining()) {
            int tag = buf.getU1();
            int time = buf.getU4();
            int recordLength = buf.getU4();
            if (tag == 0x0C || tag == 0x1C) {
                int endOfRecord = buf.position() + recordLength;
                while (buf.position() < endOfRecord) {
                    int subtag = buf.getU1();
                    if (handleIrrelevantSubtags(subtag, buf, idSize8, idSize)) {
                        // Nothing to do here.
                    } else if (handlePossiblyRelevantSubtags(subtag, buf, idSize8, idSize,
                            /* firstPass = */ false)) {
                        // Nothing to do here.
                    } else if (subtag == 0x21) { // INSTANCE DUMP
                        long objectId = buf.getId(idSize8);
                        int stackSerialNumber = buf.getU4();
                        long classId = buf.getId(idSize8);
                        int numBytes = buf.getU4();

                        // We check for null first because we can't cast a null value to long.
                        long stringId = classes.get(classId) != null ? classes.get(classId) : -1;
                        int originalPosition = buf.position();

                        // We use field names instead of relying on the alphabetical field order,
                        // since it's less likely that an existing field name will be changed than
                        // a new field added.
                        String className = strings.get(stringId);
                        if (DUMPDATA_CLASSNAME.equals(className)) {
                            for (Field field : dumpDataFields) {
                                if ("buffers".equals(field.name)) {
                                    // Used in OBJECT ARRAY DUMP.
                                    dumpDataBuffersId = buf.getId(idSize8);
                                } else if ("natives".equals(field.name)) {
                                    // Used in PRIMITIVE ARRAY DUMP.
                                    dumpDataNativesId = buf.getId(idSize8);
                                } else if ("sizes".equals(field.name)) {
                                    // Used in PRIMITIVE ARRAY DUMP.
                                    dumpDataSizesId = buf.getId(idSize8);
                                } else {
                                    handleIrrelevantField(field, buf, idSize8);
                                }
                            }
                        } else if (BITMAP_CLASSNAME.equals(className)) {
                            int height = -1;
                            int width = -1;
                            long nativePtr = -1;
                            for (Field field : bitmapFields) {
                                if ("mHeight".equals(field.name)) {
                                    height = buf.getInt();
                                } else if ("mWidth".equals(field.name)) {
                                    width = buf.getInt();
                                } else if ("mNativePtr".equals(field.name)) {
                                    nativePtr = buf.getLong();
                                } else {
                                    handleIrrelevantField(field, buf, idSize8);
                                }
                            }
                            dimensions.put(nativePtr, new Dimensions(width, height));
                        }
                        buf.seek(originalPosition + numBytes);
                    } else if (subtag == 0x22) { // OBJECT ARRAY DUMP
                        long objectId = buf.getId(idSize8);
                        int stackSerialNumber = buf.getU4();
                        int length = buf.getU4();
                        long classId = buf.getId(idSize8);

                        // We check for null first because we can't cast a null value to long.
                        long stringId = classes.get(classId) != null ? classes.get(classId) : -1;

                        if (objectId == dumpDataBuffersId) {
                            for (int i = 0; i < length; i++) {
                                long referenceId = buf.getId(idSize8);
                                bitmapBufferRefs.add(referenceId);
                            }
                        } else {
                            buf.skip(length * idSize);
                        }
                    } else if (subtag == 0x23) { // PRIMITIVE ARRAY DUMP
                        long objectId = buf.getId(idSize8);
                        int stackSerialNumber = buf.getU4();
                        int length = buf.getU4();
                        Type type = buf.getType();

                        // These array dumps always seem to be encountered after the IDs
                        // representing them have been found, including the entire set of IDs for
                        // bitmapBufferRefs. If this assumption ever fails, it will be logged below.
                        if (bitmapBufferRefs.contains(objectId)) {
                            byte[] byteArray = new byte[length];
                            buf.getBytes(byteArray);
                            bitmapBuffers.put(objectId, byteArray);
                        } else if (objectId == dumpDataNativesId) {
                            for (int i = 0; i < length; i++) {
                                long nativePtr = buf.getLong();
                                nativePtrs.add(nativePtr);
                            }
                        } else if (objectId == dumpDataSizesId) {
                            for (int i = 0; i < length; i++) {
                                int size = buf.getInt();
                                sizes.add(size);
                            }
                        } else {
                            buf.skip(length * type.size(idSize));
                        }
                    } else {
                        Log.e(TAG, String.format("subtag %x not found", subtag));
                    }
                }
            } else {
                buf.skip(recordLength);
            }
        }

        // This case shouldn't occur as DumpData arrays should be of the same length.
        if (nativePtrs.size() != bitmapBufferRefs.size() ||
                nativePtrs.size() != sizes.size()) {
            Log.e(TAG, "Some bitmap info is missing; no bitmaps will be dumped. Item counts:");
            Log.e(TAG, String.format("nativePtrs: %d, bitmapBufferRefs: %d, sizes: %d",
                    nativePtrs.size(), bitmapBufferRefs.size(), sizes.size()));
        } else {
            if (bitmapBuffers.size() != nativePtrs.size()) {
                Log.w(TAG, String.format("%d bitmaps were found on the heap, but DumpData " +
                        "contains info for %d bitmaps.", bitmapBuffers.size(), nativePtrs.size()));
            }
            // nativePtrs, sizes, and bitmapBufferRefs are arrays held by DumpData and can be
            // traversed in order. bitmapBuffers is populated in the order that instances were
            // encountered in the heap dump, so must be indexed into using bitmapBufferRefs.
            for (int i = 0; i < nativePtrs.size(); i++) {
                Dimensions dim = dimensions.getOrDefault(nativePtrs.get(i), new Dimensions(0, 0));
                byte[] buffer = bitmapBuffers.get(bitmapBufferRefs.get(i));
                if (buffer != null) {
                    writeBitmap(file.getParent(), i, dim, sizes.get(i), BitmapFactory.decodeStream(
                            new ByteArrayInputStream(buffer)));
                }
            }
        }
    }

    // Writes the input Bitmap as a PNG to the input directory.
    private static boolean writeBitmap(String dir, int index, Dimensions dimensions, int size,
            Bitmap bitmap) {
        String path = String.format("%s/bitmap-%d-(%dx%d)-(%dB).png", dir, index, dimensions.width,
                dimensions.height, size);
        Log.i(TAG, "Writing bitmap to " + path);
        try (OutputStream os = new FileOutputStream(new File(path))) {
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, os);
            os.flush();
            return true;
        } catch (Exception e) {
            Log.i(TAG, "Failed to write bitmap to " + path);
            return false;
        }
    }

    // These Types are used to identify object types during heap dump parsing.
    enum Type {
        OBJECT("Object", 0),
        BOOLEAN("boolean", 1),
        CHAR("char", 2),
        FLOAT("float", 4),
        DOUBLE("double", 8),
        BYTE("byte", 1),
        SHORT("short", 2),
        INT("int", 4),
        LONG("long", 8);

        public final String name;
        private final int size;

        int size(int refSize) {
            return (size == 0) ? refSize : size;
        }

        Type(String name, int size) {
            this.name = name;
            this.size = size;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    static Type[] TYPES = new Type[] {
        null, null, Type.OBJECT, null, Type.BOOLEAN, Type.CHAR, Type.FLOAT, Type.DOUBLE,
        Type.BYTE, Type.SHORT, Type.INT, Type.LONG
    };

    // Given some irrelevant subtag for HEAP DUMP and HEAP DUMP SEGMENT, skip the appropriate number
    // of bytes in the buffer. Returns true if the subtag was processed.
    private static boolean handleIrrelevantSubtags(int subtag, HprofBuffer buf, boolean idSize8,
            int idSize) {
        if (subtag == 0x01) { // ROOT JNI GLOBAL
            long objectId = buf.getId(idSize8);
            long refId = buf.getId(idSize8);
        } else if (subtag == 0x02) { // ROOT JNI LOCAL
            long objectId = buf.getId(idSize8);
            int threadSerialNumber = buf.getU4();
            int frameNumber = buf.getU4();
        } else if (subtag == 0x03) { // ROOT JAVA FRAME
            long objectId = buf.getId(idSize8);
            int threadSerialNumber = buf.getU4();
            int frameNumber = buf.getU4();
        } else if (subtag == 0x04) { // ROOT NATIVE STACK
            long objectId = buf.getId(idSize8);
            int threadSerialNumber = buf.getU4();
        } else if (subtag == 0x05) { // ROOT STICKY CLASS
            long objectId = buf.getId(idSize8);
        } else if (subtag == 0x06) { // ROOT THREAD BLOCK
            long objectId = buf.getId(idSize8);
            int threadSerialNumber = buf.getU4();
        } else if (subtag == 0x07) { // ROOT MONITOR USED
            long objectId = buf.getId(idSize8);
        } else if (subtag == 0x08) { // ROOT THREAD OBJECT
            long objectId = buf.getId(idSize8);
            int threadSerialNumber = buf.getU4();
            int stackSerialNumber = buf.getU4();
        } else if (subtag == 0x89) { // ROOT INTERNED STRING
            long objectId = buf.getId(idSize8);
        } else if (subtag == 0x8a) { // ROOT FINALIZING
            long objectId = buf.getId(idSize8);
        } else if (subtag == 0x8b) { // ROOT DEBUGGER
            long objectId = buf.getId(idSize8);
        } else if (subtag == 0x8d) { // ROOT VM INTERNAL
            long objectId = buf.getId(idSize8);
        } else if (subtag == 0x8e) { // ROOT JNI MONITOR
            long objectId = buf.getId(idSize8);
            int threadSerialNumber = buf.getU4();
            int frameNumber = buf.getU4();
        } else if (subtag == 0xfe) { // HEAP DUMP INFO
            int type = buf.getU4();
            long stringId = buf.getId(idSize8);
        } else if (subtag == 0xff) { // ROOT UNKNOWN
            long objectId = buf.getId(idSize8);
        } else {
            return false;
        }
        return true;
    }

    // Given some subtag, skip the appropriate number of bytes in the buffer if the subtag isn't
    // relevant for the current pass. Returns true if the subtag was processed.
    private static boolean handlePossiblyRelevantSubtags(int subtag, HprofBuffer buf,
            boolean idSize8, int idSize, boolean firstPass) {
        if (firstPass && subtag == 0x21) { // INSTANCE DUMP
            long objectId = buf.getId(idSize8);
            int stackSerialNumber = buf.getU4();
            long classId = buf.getId(idSize8);
            int numBytes = buf.getU4();
            buf.skip(numBytes);
        } else if (firstPass && subtag == 0x22) { // OBJECT ARRAY DUMP
            long objectId = buf.getId(idSize8);
            int stackSerialNumber = buf.getU4();
            int length = buf.getU4();
            long classId = buf.getId(idSize8);
            buf.skip(length * idSize);
        } else if (firstPass && subtag == 0x23) { // PRIMITIVE ARRAY DUMP
            long objectId = buf.getId(idSize8);
            int stackSerialNumber = buf.getU4();
            int length = buf.getU4();
            Type type = buf.getType();
            buf.skip(length * type.size(idSize));
        } else if (!firstPass && subtag == 0x20) { // CLASS DUMP
            long objectId = buf.getId(idSize8);
            int stackSerialNumber = buf.getU4();
            long superClassId = buf.getId(idSize8);
            long classLoaderId = buf.getId(idSize8);
            long signersId = buf.getId(idSize8);
            long protectionId = buf.getId(idSize8);
            long reserved1 = buf.getId(idSize8);
            long reserved2 = buf.getId(idSize8);
            int instanceSize = buf.getU4();

            int constantPoolSize = buf.getU2();
            for (int i = 0; i < constantPoolSize; i++) {
                int index = buf.getU2();
                Type type = buf.getType();
                buf.skip(type.size(idSize));
            }

            int numStaticFields = buf.getU2();
            for (int i = 0; i < numStaticFields; i++) {
                long nameId = buf.getId(idSize8);
                Type type = buf.getType();
                buf.skip(type.size(idSize));
            }

            int numInstanceFields = buf.getU2();
            for (int i = 0; i < numInstanceFields; i++) {
                long nameId = buf.getId(idSize8);
                Type type = buf.getType();
            }
        } else {
            return false;
        }
        return true;
    }

    // Convenience class for representing the names and types of android.graphics.Bitmap and
    // android.graphics.Bitmap$DumpData instance fields.
    private static class Field {
        String name;
        Type type;
        Field(String name, Type type) {
            this.name = name;
            this.type = type;
        }
    }

    // Given some instance field, skip the appropriate number of bytes. android.graphics.Bitmap and
    // android.graphics.Bitmap$DumpData are only expected to have ints, longs, and booleans as
    // irrelevant fields.
    private static void handleIrrelevantField(Field field, HprofBuffer buf, boolean idSize8) {
        switch (field.type) {
            case Type.INT: {
                buf.getInt();
                break;
            }
            case Type.LONG: {
                buf.getLong();
                break;
            }
            case Type.BOOLEAN: {
                buf.getBool();
                break;
            }
            case Type.OBJECT: {
                buf.getId(idSize8);
                break;
            }
            default:
                Log.e(TAG, String.format("Instance field %s is of unexpected type %s", field.name,
                        field.type));
        }
    }

    // Convenience class for storing bitmap dimensions.
    private static class Dimensions {
        int width;
        int height;
        Dimensions(int width, int height) {
            this.width = width;
            this.height = height;
        }
    }

    private static final Set<String> RELEVANT_STRINGS = new HashSet<>(Arrays.asList(
            new String[]{
                BITMAP_CLASSNAME, DUMPDATA_CLASSNAME,
                "buffers", "natives", "sizes",
                "mHeight", "mWidth", "mNativePtr"}));
    private static boolean isRelevantString(String string) {
        return string != null && RELEVANT_STRINGS.contains(string);
    }

    private static String getOutputDirectory(String date) {
        return String.format("%s/am-heap-dump-%s", TRACE_DIRECTORY, date);
    }

}

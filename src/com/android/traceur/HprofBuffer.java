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

import static com.android.traceur.DumpHeapUtils.Type;

import java.nio.ByteBuffer;

/**
 * Utility class for reading a ByteBuffer that represents the contents of a .hprof file.
 * .hprof files are binary representations of heap dumps.
 */
public class HprofBuffer {

    ByteBuffer buf;

    HprofBuffer(ByteBuffer buf) {
        this.buf = buf;
    }

    // getU1, U2, and U4 return the next 1, 2, or 4 unsigned bytes.
    int getU1() {
        return buf.get() & 0xFF;
    }
    int getU2() {
        return buf.getShort() & 0xFFFF;
    }
    int getU4() {
        return buf.getInt();
    }
    long getId(boolean idSize8) {
        return idSize8 ? getLong() : (getInt() & 0xFFFFFFFFL);
    }
    boolean getBool() {
        return buf.get() != 0;
    }
    char getChar() {
        return buf.getChar();
    }
    float getFloat() {
        return buf.getFloat();
    }
    double getDouble() {
        return buf.getDouble();
    }
    byte getByte() {
        return buf.get();
    }
    void getBytes(byte[] bytes) {
        buf.get(bytes);
    }
    short getShort() {
        return buf.getShort();
    }
    int getInt() {
        return buf.getInt();
    }
    long getLong() {
        return buf.getLong();
    }
    Type getType() {
        int id = getU1();
        Type type = id < DumpHeapUtils.TYPES.length ? DumpHeapUtils.TYPES[id] : null;
        return type;
    }
    boolean hasRemaining() {
        return buf.hasRemaining();
    }
    int position() {
        return buf.position();
    }
    void seek(int position) {
        buf.position(position);
    }
    void skip(int delta) {
        seek(buf.position() + delta);
    }
}

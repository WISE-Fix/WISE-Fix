"""Generate parser-complete illustrative contexts and actual unified diffs."""
import difflib
from pathlib import Path


PRE125='''void *memcpy(void *, const void *, unsigned long);
typedef struct { unsigned char *bitmap; } Tga;
int decode(Tga *tga, unsigned char *decompression_buffer, int buffer_caret,
           int bitmap_caret, int encoded_pixels, int pixel_block_size, int image_block_size) {
    int i, j;
    if (encoded_pixels != 0) {
        if (!((buffer_caret + encoded_pixels * pixel_block_size) < image_block_size)) {
            return -1;
        }
        for (i = 0; i < encoded_pixels; i++)
            for (j = 0; j < pixel_block_size; j++, bitmap_caret++)
                tga->bitmap[bitmap_caret] = decompression_buffer[buffer_caret + j];
    }
    return 0;
}
'''
POST125='''void *memcpy(void *, const void *, unsigned long);
typedef struct { unsigned char *bitmap; } Tga;
int decode(Tga *tga, unsigned char *decompression_buffer, int buffer_caret,
           int bitmap_caret, int encoded_pixels, int pixel_block_size, int image_block_size) {
    int i, j;
    if ((bitmap_caret + encoded_pixels * pixel_block_size) >= image_block_size) {
        return -1;
    }
    for (i = 0; i < encoded_pixels; i++) {
        memcpy(tga->bitmap + bitmap_caret, decompression_buffer + buffer_caret, pixel_block_size);
        bitmap_caret += pixel_block_size;
    }
    return 0;
}
'''
PRE119='''typedef unsigned long MagickSizeType;
typedef unsigned long size_t;
typedef struct { char *name; } Layer;
int ReadBlobByte(void *);
int ReadBlob(void *, size_t, char *);
int decode(void *image, Layer *layer_info, int i) {
    MagickSizeType length, combined_length = 0;
    length = (MagickSizeType) ReadBlobByte(image);
    combined_length += length + 1;
    if (length > 0) ReadBlob(image, (size_t) length++, layer_info[i].name);
    return 0;
}
'''
POST119=PRE119.replace('(MagickSizeType) ReadBlobByte(image)','(MagickSizeType) (unsigned char) ReadBlobByte(image)')


def diff(before,after,file):
    return ''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/'+file,tofile='b/'+file))



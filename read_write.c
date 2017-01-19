#include "testfs.h"
#include "list.h"
#include "super.h"
#include "block.h"
#include "inode.h"
#define MAX_BLOCK NR_DIRECT_BLOCKS + NR_INDIRECT_BLOCKS + NR_INDIRECT_BLOCKS*NR_INDIRECT_BLOCKS - 1

/* given logical block number, read the corresponding physical block into block.
 * return physical block number.
 * returns 0 if physical block does not exist.
 * returns negative value on other errors. */
static int
testfs_read_block(struct inode *in, int log_block_nr, char *block)
{
    if (log_block_nr > MAX_BLOCK)
        return -EFBIG;
	int phy_block_nr = 0;

    assert(log_block_nr >= 0);
    if (log_block_nr < NR_DIRECT_BLOCKS) {
        phy_block_nr = (int) in->in.i_block_nr[log_block_nr];
    } else {
        log_block_nr -= NR_DIRECT_BLOCKS;

        if (log_block_nr >= NR_INDIRECT_BLOCKS) {
            log_block_nr -= NR_INDIRECT_BLOCKS;
            if (in->in.i_dindirect > 0) {
                read_blocks(in->sb, block, in->in.i_dindirect, 1);
                int temp = log_block_nr / (BLOCK_SIZE / 4);
                phy_block_nr = ((int *) block)[temp];
                read_blocks(in->sb, block, phy_block_nr, 1);
                if (phy_block_nr > 0) {
                    int temp2 = log_block_nr % NR_INDIRECT_BLOCKS;
                    phy_block_nr = ((int *) block)[temp2];
                    read_blocks(in->sb, block, phy_block_nr, 1);
                }
            }
            return phy_block_nr;
        }
        if (in->in.i_indirect > 0) {
            read_blocks(in->sb, block, in->in.i_indirect, 1);
            phy_block_nr = ((int *) block)[log_block_nr];
        }
    }
    if (phy_block_nr > 0) {
        read_blocks(in->sb, block, phy_block_nr, 1);
    } else {
        /* we support sparse files by zeroing out a block that is not
         * allocated on disk. */
        bzero(block, BLOCK_SIZE);
    }
    return phy_block_nr;
}

int
testfs_read_data(struct inode *in, char *buf, off_t start, size_t size)
{
    char block[BLOCK_SIZE];
    long block_nr = start / BLOCK_SIZE;
    long block_ix = start % BLOCK_SIZE;
    int ret;
    int m_size = size;
    if (block_nr > MAX_BLOCK)
        return -EFBIG;
    assert(buf);
    if (start + (off_t) size > in->in.i_size) {
        size = in->in.i_size - start;
    }
    if (block_ix + size > BLOCK_SIZE) {
read:
        if (block_ix + size <= BLOCK_SIZE)
            goto resume;
        if ((ret = testfs_read_block(in, block_nr, block)) < 0)
            return ret;
        memcpy(buf, block + block_ix, BLOCK_SIZE - block_ix);
        block_nr++;
        if (block_nr > MAX_BLOCK)
            return -EFBIG;
        m_size = m_size - BLOCK_SIZE - block_ix;
        buf = buf + BLOCK_SIZE - block_ix;
        block_ix = 0;
        if (m_size > BLOCK_SIZE)
        {
            goto read;
        }
    }
resume:
    if ((ret = testfs_read_block(in, block_nr, block)) < 0)
        return ret;
    memcpy(buf, block + block_ix, size);
    /* return the number of bytes read or any error */
    return size;
}

/* given logical block number, allocate a new physical block, if it does not
 * exist already, and return the physical block number that is allocated.
 * returns negative value on error. */
static int
testfs_allocate_block(struct inode *in, int log_block_nr, char *block)
{
    int phy_block_nr;
    char indirect[BLOCK_SIZE];

    int indirect_allocated = 0;

    assert(log_block_nr >= 0);
    phy_block_nr = testfs_read_block(in, log_block_nr, block);

    if (phy_block_nr != 0)
        return phy_block_nr;

    /* allocate a direct block */
    if (log_block_nr < NR_DIRECT_BLOCKS) {
        assert(in->in.i_block_nr[log_block_nr] == 0);
        phy_block_nr = testfs_alloc_block_for_inode(in);
        if (phy_block_nr >= 0) {
            in->in.i_block_nr[log_block_nr] = phy_block_nr;
        }
        return phy_block_nr;
    }

    log_block_nr -= NR_DIRECT_BLOCKS;
    if (log_block_nr >= NR_INDIRECT_BLOCKS) {
        log_block_nr = log_block_nr - NR_INDIRECT_BLOCKS;
        char tmp_index[BLOCK_SIZE];
        bzero(tmp_index, BLOCK_SIZE);
        if (in->in.i_dindirect == 0) {
            phy_block_nr = testfs_alloc_block_for_inode(in);
            if (phy_block_nr < 0) {
                return phy_block_nr;
            }
            in->in.i_dindirect = phy_block_nr;
        }
        else {
            read_blocks(in->sb, tmp_index, in->in.i_dindirect, 1);
        }
        int temp = log_block_nr / (BLOCK_SIZE / 4);
        char tmp_index2[BLOCK_SIZE];
        bzero(tmp_index2, BLOCK_SIZE);
        int check = ((int *) tmp_index)[temp];
        if (check == 0) {
            phy_block_nr = testfs_alloc_block_for_inode(in);
            if (phy_block_nr < 0) {
                return phy_block_nr;
            }
            ((int*) tmp_index)[temp] = phy_block_nr;
            write_blocks(in->sb, tmp_index, in->in.i_dindirect, 1);
        }
        else {
            read_blocks(in->sb, tmp_index2, ((int*) tmp_index)[temp], 1);
        }
        phy_block_nr = testfs_alloc_block_for_inode(in);
        if (phy_block_nr >= 0) {
                int temp2 = log_block_nr % NR_INDIRECT_BLOCKS;
                ((int*) tmp_index2)[temp2] = phy_block_nr;
                write_blocks(in->sb, tmp_index2, ((int*) tmp_index)[temp], 1);
                return phy_block_nr;
            }
        else if (phy_block_nr == -ENOSPC){
            testfs_free_block_from_inode(in, ((int*) tmp_index)[temp]);
            ((int*) tmp_index)[temp] = 0;
            write_blocks(in->sb, tmp_index, in->in.i_dindirect, 1);
            return phy_block_nr;
        }
    }
    if (in->in.i_indirect == 0) {
        bzero(indirect, BLOCK_SIZE);
        phy_block_nr = testfs_alloc_block_for_inode(in);
        if (phy_block_nr < 0)
            return phy_block_nr;
        indirect_allocated = 1;
        in->in.i_indirect = phy_block_nr;
    } else { /* read indirect block */
        read_blocks(in->sb, indirect, in->in.i_indirect, 1);
    }

    /* allocate direct block */
    assert(((int *) indirect)[log_block_nr] == 0);
    phy_block_nr = testfs_alloc_block_for_inode(in);

    if (phy_block_nr >= 0) {
        /* update indirect block */
        ((int *) indirect)[log_block_nr] = phy_block_nr;
        write_blocks(in->sb, indirect, in->in.i_indirect, 1);
    } else if (indirect_allocated) {
        /* free the indirect block that was allocated */
        testfs_free_block_from_inode(in, in->in.i_indirect);
        in->in.i_indirect = 0;
    }
    return phy_block_nr;
}

int
testfs_write_data(struct inode *in, const char *buf, off_t start, size_t size) {
    char block[BLOCK_SIZE];
    long block_nr = start / BLOCK_SIZE;
    long block_ix = start % BLOCK_SIZE;
    off_t offS = start + (BLOCK_SIZE - block_ix);
    if (block_nr > MAX_BLOCK)
        return -EFBIG;
    int ret;
    if (block_ix + size > BLOCK_SIZE) {
        ret = testfs_allocate_block(in, block_nr, block);
        if (ret < 0) 
            return ret;
        size_t size_in_block = BLOCK_SIZE - block_ix;
	const char* temp_buf;
        size_t w_o_offS = size - size_in_block;
        block_nr++;
        int counter = 1;
	goto write_to_block;
 write:     
            ret = testfs_allocate_block(in, block_nr, block);
            if (ret < 0) {
                in->in.i_size = MAX(in->in.i_size, offS);
                in->i_flags |= I_FLAGS_DIRTY;
                return ret;
            }
            if (w_o_offS >= BLOCK_SIZE) {
                size_in_block = BLOCK_SIZE;
                w_o_offS -= BLOCK_SIZE;
		temp_buf = buf + size - BLOCK_SIZE - w_o_offS;
		block_nr++;
            	counter++;
		goto write_to_block;
            }
            else if (w_o_offS < BLOCK_SIZE) {
                size_in_block = w_o_offS;
		temp_buf = buf + size - size_in_block;
		block_nr++;
            	counter++;
		w_o_offS = 0;
		goto write_to_block;
            }
            else if (w_o_offS == 0) {
                goto resume1;
            }
write_to_block:
	if (counter == 1)
            memcpy(block + block_ix, buf, size_in_block);
	else
	    memcpy (block, temp_buf, size_in_block);
        write_blocks(in->sb, block, ret, 1);
	if (counter != 1)
	    offS = offS + size_in_block;
        if (counter < ((long)(block_ix + size) + BLOCK_SIZE - 1)/ BLOCK_SIZE)
            goto write;
	else goto resume1;
resume1:
        in->in.i_size = MAX(in->in.i_size, offS);
        in->i_flags |= I_FLAGS_DIRTY;
        return size;
    }
          /* ret is the newly allocated physical block number */
    ret = testfs_allocate_block(in, block_nr, block);
    if (ret < 0)
        return ret;
    memcpy(block + block_ix, buf, size);
    write_blocks(in->sb, block, ret, 1);
    /* increment i_size by the number of bytes written. */
    if (size > 0)
        in->in.i_size = MAX(in->in.i_size, start + (off_t) size);
    in->i_flags |= I_FLAGS_DIRTY;
    /* return the number of bytes written or any error */
    return size;
}

int
testfs_free_blocks(struct inode *in) {
    int e_block_nr;
    int i;
    /* last block number */
    e_block_nr = DIVROUNDUP(in->in.i_size, BLOCK_SIZE);

    /* remove direct blocks */
    for (i = 0; i < e_block_nr && i < NR_DIRECT_BLOCKS; i++) {
        if (in->in.i_block_nr[i] == 0)
            continue;
        testfs_free_block_from_inode(in, in->in.i_block_nr[i]);
        in->in.i_block_nr[i] = 0;
    }
    e_block_nr -= NR_DIRECT_BLOCKS;

    /* remove indirect blocks */
    if (in->in.i_indirect > 0) {
        char block[BLOCK_SIZE];
        read_blocks(in->sb, block, in->in.i_indirect, 1);
        for (i = 0; i < e_block_nr && i < NR_INDIRECT_BLOCKS; i++) {
            testfs_free_block_from_inode(in, ((int *) block)[i]);
            ((int *) block)[i] = 0;
        }
        testfs_free_block_from_inode(in, in->in.i_indirect);
        in->in.i_indirect = 0;
    }

    e_block_nr -= NR_INDIRECT_BLOCKS;
    if (e_block_nr >= 0) {
        if (in->in.i_dindirect > 0) {
            char i1[BLOCK_SIZE];
            read_blocks(in->sb, i1, in->in.i_dindirect, 1);
            for (i = 0; i < NR_INDIRECT_BLOCKS ; i++) {
                if (((int *) i1)[i] != 0) {
                    int j;
                    char i2[BLOCK_SIZE];
                    read_blocks(in->sb, i2, ((int *) i1)[i], 1);
                    for (j = 0; j < NR_INDIRECT_BLOCKS; j++) {
                        if (((int *) i2)[j] != 0)
                        {   
                            testfs_free_block_from_inode(in, ((int *) i2)[j]);
                            ((int *) i2)[j] = 0;
                        }
                    }
                }
                testfs_free_block_from_inode(in, ((int *) i1)[i]);
                ((int *) i1)[i] = 0;
            }
            testfs_free_block_from_inode(in, in->in.i_dindirect);
            in->in.i_dindirect = 0;
        }
    }
    in->in.i_size = 0;
    in->i_flags |= I_FLAGS_DIRTY;
    return 0;
}

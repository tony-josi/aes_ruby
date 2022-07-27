
require './aes_lut.rb'

module AES_CORE

    # /* AES Word size */
    AES_WORD_SIZE   					= (4)
    
    # /* 12.8 KB per data segment. */
    AES_DATA_SIZE_PER_SEGMENT			= (12800)
    FILE_IO_CHUNK_SIZE_BYTES			= (12800000 * 2)
    MAX_ALGO_WORKER_THREAD_COUNT		= (50)
    
    # /* Metdata size should be (AES_WORD_SIZE * AES_WORD_SIZE) */ 
    AES_META_DATA_SIZE				    = (AES_WORD_SIZE * AES_WORD_SIZE)  
    AES_META_DATA_PADD_SIZE_OFFSET	    = (0) 
    AES_META_DATA_CHECK_SUM_OFFSET	    = (8) 
    
    # /* Maximum supported plain text key size. */
    MAX_SUPPORTED_PLAIN_KEY_SIZE		= (32)
    
    # /* Plain text key size. */
    AES128_PLAIN_KEY_SIZE				= (16)
    AES192_PLAIN_KEY_SIZE				= (24)
    AES256_PLAIN_KEY_SIZE				= (32)

    def aes_expand_key(raw_key)

        raw_key_arr = Array.new(@actual_key_len, 0)
        raw_key_len = raw_key.length > @actual_key_len ? @actual_key_len : raw_key.length
        raw_key_arr[0 .. (raw_key_len - 1)] = raw_key.bytes[0 .. (raw_key_len - 1)]

        expanded_key_arr = raw_key_arr.dup

        #p expanded_key_arr

        # Increment an offset to the current filled 
        # position in the expanded key output array */
        cur_exp_key_offset = 0
        cur_exp_key_offset += @actual_key_len;

        round_key_index = 1

        while cur_exp_key_offset < @expanded_key_len
        
            expanded_key_start_idx = cur_exp_key_offset - AES_WORD_SIZE

            temp_key_arr_1 = expanded_key_arr[expanded_key_start_idx .. (expanded_key_start_idx + AES_WORD_SIZE)]

            temp_key_arr_2 = aes_key_scheduler(round_key_index, temp_key_arr_1)

            temp_key_arr_1[0 .. (AES_WORD_SIZE - 1)] = expanded_key_arr[(cur_exp_key_offset - @actual_key_len) .. (cur_exp_key_offset - @actual_key_len + AES_WORD_SIZE - 1)]

            temp_key_arr_1 = aes_xor_word(temp_key_arr_1, temp_key_arr_2);
            expanded_key_arr += temp_key_arr_1

            cur_exp_key_offset += AES_WORD_SIZE;
    
            #/* Compute key for remaining words in the block */
            cur_exp_key_offset = aes_compute_remaining_words(3, expanded_key_arr, cur_exp_key_offset, \
            @expanded_key_len, @actual_key_len);

            #p expanded_key_arr
            
            if @actual_key_len == AES256_PLAIN_KEY_SIZE 
                #/* Do special key schedule if i >= N & (i % n) == 4 */
                cur_exp_key_offset = aes_key_scheduler_4th_word(expanded_key_arr, cur_exp_key_offset, \
                @expanded_key_len, @actual_key_len)

                #p expanded_key_arr
                
                cur_exp_key_offset = aes_compute_remaining_words(3, expanded_key_arr, cur_exp_key_offset, \
                @expanded_key_len, @actual_key_len)

                #p expanded_key_arr
    
            elsif @actual_key_len == AES192_PLAIN_KEY_SIZE 
                cur_exp_key_offset = aes_compute_remaining_words(2, expanded_key_arr, cur_exp_key_offset, \
                @expanded_key_len, @actual_key_len)

            end
            
            round_key_index += 1

            

        end
        
        # if @key_len == 192
        #     p "192 bits"
        # else
        #     p "unknown"
        # end
        expanded_key_arr
    end

    def aes_key_scheduler(round, ip_arr)

        op_arr = Array.new(AES_WORD_SIZE)

        for i in 0..(AES_WORD_SIZE - 1) do
            # p i, op_arr, ip_arr
            op_arr[i] = ip_arr[i + 1]
        end
        op_arr[3] = ip_arr[0]

        for i in 0..(AES_WORD_SIZE - 1) do
            op_arr[i] = AES_S_BOX[ op_arr[i] ]
        end    

        if round < AES_RCON.length
            op_arr[0] ^= AES_RCON[round]
        else
            raise RuntimeError
        end

        op_arr

    end


    def aes_xor_word(arr_a, arr_b)
        
        op_arr = []
        #p arr_a, arr_b
        for i in 0..(AES_WORD_SIZE - 1) do
            op_arr[i] = arr_a[i] ^ arr_b[i]
        end

        op_arr

    end

    def aes_compute_remaining_words(words_required, expanded_key_arr, cur_exp_key_offset, expanded_key_len, actual_key_len)

        temp_arr_1 = []
        temp_arr_2 = []

        i = 0

        while (i < words_required) && (cur_exp_key_offset < expanded_key_len)

            temp_arr_1_indx = cur_exp_key_offset - AES_WORD_SIZE
            temp_arr_1 = expanded_key_arr[temp_arr_1_indx .. (temp_arr_1_indx + AES_WORD_SIZE)]
            #p "#{temp_arr_1_indx}, #{expanded_key_arr.length}, #{words_required}, #{i}, #{cur_exp_key_offset}, #{expanded_key_len}"

            temp_arr_1_indx = cur_exp_key_offset - actual_key_len
            temp_arr_2 = expanded_key_arr[temp_arr_1_indx .. (temp_arr_1_indx + AES_WORD_SIZE)]
            #p temp_arr_1_indx, expanded_key_arr.length

            temp_arr_1 = aes_xor_word(temp_arr_1, temp_arr_2)

            for j in cur_exp_key_offset .. (cur_exp_key_offset + AES_WORD_SIZE - 1) do

                expanded_key_arr[j] = temp_arr_1[j - cur_exp_key_offset]

            end

            cur_exp_key_offset += AES_WORD_SIZE

            i += 1
        end

        cur_exp_key_offset
    end

    def aes_key_scheduler_4th_word(expanded_key_arr, cur_exp_key_offset, expanded_key_len, actual_key_len)

        if cur_exp_key_offset < expanded_key_len
        
            temp_arr_1_indx = cur_exp_key_offset - AES_WORD_SIZE
            temp_arr_1 = expanded_key_arr[temp_arr_1_indx .. (temp_arr_1_indx + AES_WORD_SIZE)]  
            
            for i in 0 .. (AES_WORD_SIZE - 1) do
                temp_arr_1[i] = AES_S_BOX[ temp_arr_1[i] ]
            end

            temp_arr_1_indx = cur_exp_key_offset - actual_key_len
            temp_arr_2 = expanded_key_arr[temp_arr_1_indx .. (temp_arr_1_indx + AES_WORD_SIZE)]  

            temp_arr_1 = aes_xor_word(temp_arr_1, temp_arr_2)

            for j in cur_exp_key_offset .. (cur_exp_key_offset + AES_WORD_SIZE - 1) do

                expanded_key_arr[j] = temp_arr_1[j - cur_exp_key_offset]

            end

            cur_exp_key_offset += AES_WORD_SIZE
            cur_exp_key_offset

        else
            return cur_exp_key_offset

        end

    end
    
end

class AES
    include AES_CORE

    def initialize(key_len)
        case key_len
        when 128
            @key_len = key_len
            @round_num = 10
            @actual_key_len = AES128_PLAIN_KEY_SIZE
            @expanded_key_len = 176
        when 192
            @key_len_bits = 192
            @round_num = 12
            @actual_key_len = AES192_PLAIN_KEY_SIZE
            @expanded_key_len = 208;
        when 256
            @key_len_bits = 256
            @round_num = 14
            @actual_key_len = AES256_PLAIN_KEY_SIZE
            @expanded_key_len = 240
        else 
            puts "Unsupported Key Length, supports 128/192/256"
            raise ArgumentError
        end
    
    end


end

aes_obj = AES.new(256)
exp_k = aes_obj.aes_expand_key("12345678123456781234567812345678")
p exp_k
p "Length: #{exp_k.length}"
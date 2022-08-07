require './aes_consts.rb'

module AES_CORE_UTILS

    def aes_xor_word(arr_a, arr_b)
        
        op_arr = []

        for i in 0..(AES_WORD_SIZE - 1) do
            op_arr[i] = arr_a[i] ^ arr_b[i]
        end
        
        op_arr
        
    end

    def aes_transposition(arr_out, arr_in, offset)

        for i in 0..(AES_WORD_SIZE - 1) do
            for j in 0..(AES_WORD_SIZE - 1) do
                arr_out[i][j] = arr_in[ offset + (j * 4) + i ]
            end
        end

    end

    def aes_rev_transposition(arr_out, arr_in, offset)

        for i in 0..(AES_WORD_SIZE - 1) do
            for j in 0..(AES_WORD_SIZE - 1) do
                arr_out[ offset + (j * 4) + i ] = arr_in[[i][j]
            end
        end

    end

end
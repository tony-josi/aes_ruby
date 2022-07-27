
require './aes_lut.rb'
require './aes_consts.rb'
require './aes_key_expansion.rb'

module AES_CORE

    include AES_KEY_EXPAND

    def aes_xor_word(arr_a, arr_b)
        
        op_arr = []
        
        #p arr_a, arr_b
        for i in 0..(AES_WORD_SIZE - 1) do
            op_arr[i] = arr_a[i] ^ arr_b[i]
        end
        
        op_arr
        
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
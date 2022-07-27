def aes_key_scheduler(round, ip_arr)

    op_arr = []

    for i in 2..(4 - 1) do
        op_arr[i] = i
    end


    op_arr

end

module A
    def say_hello_A
        p "A"
    end
end

module B

    include A

    def say_hello_B
        p "B"
    end

end

class ATEST

    include B

end



p aes_key_scheduler(1,[])

obj = ATEST.new
obj.say_hello_A
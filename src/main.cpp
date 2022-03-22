/** @file
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <src/sm3/sm3_gadget.hpp>
#include <iostream>
#include <vector>
#include <bits/stdc++.h>
#include <initializer_list>
#include <stdexcept>
#include <type_traits>

using namespace libsnark;

libff::bit_vector int_list_to_bits(const std::vector<unsigned long> &l, const size_t wordsize)
{
    libff::bit_vector res(wordsize*l.size());
    for (size_t i = 0; i < l.size(); ++i)
    {
        for (size_t j = 0; j < wordsize; ++j)
        {
            res[i*wordsize + j] = (*(l.begin()+i) & (1ul<<(wordsize-1-j)));
        }
    }
    return res;
}

template <typename FieldT>
void test_two_to_one(const std::vector<unsigned long> input_left,const std::vector<unsigned long> input_right,const std::vector<unsigned long> out)
{
    protoboard<FieldT> pb;

    digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
    digest_variable<FieldT> right(pb, SHA256_digest_size, "right");
    digest_variable<FieldT> output(pb, SHA256_digest_size, "output");
    sm3_two_to_one_hash_gadget<FieldT> f(pb, left, right, output, "f");
    f.generate_r1cs_constraints();
    printf("证明电路大小为: %zu\n", pb.num_constraints());

    const libff::bit_vector left_bv = int_list_to_bits(input_left, 32);
    const libff::bit_vector right_bv = int_list_to_bits(input_right, 32);
    const libff::bit_vector hash_bv = int_list_to_bits(out, 32);

    left.generate_r1cs_witness(left_bv);
    right.generate_r1cs_witness(right_bv);
    f.generate_r1cs_witness();

    output.generate_r1cs_witness(hash_bv);

    std::cout << ">> 零知识证明验证结果为:" << std::endl;
    std::cout << pb.is_satisfied() << std::endl;
}

int main(void)
{
    std::vector<unsigned long> input_left(8),input_right(8),out(8);
    std::cout << ">> 请输入填充后的消息序列:" << std::endl;
    for(int i=0;i<8;++i){
        std::cin >> std::hex >> input_left[i];
    }
    for(int i=0;i<8;++i){
        std::cin >> std::hex >> input_right[i];
    }
    std::cout << ">> 请输入待证明哈希值:" << std::endl;
    for(int i=0;i<8;++i){
        std::cin >> std::hex >> out[i];
    }
    std::cout << ">> 开始生成零知识证明电路。。。" << std::endl;

    libff::start_profiling();
    libff::default_ec_pp::init_public_params();
    test_two_to_one<libff::Fr<libff::default_ec_pp>>(input_left, input_right, out);
}



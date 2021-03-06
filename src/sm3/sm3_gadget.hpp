#ifndef SM3_GADGET_HPP_
#define SM3_GADGET_HPP_

#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <src/sm3/sm3_components.hpp>

namespace libsnark
{
    template <typename FieldT>
    class sm3_compression_function_gadget : public gadget<FieldT>
    {
    public:
        std::vector<pb_linear_combination_array<FieldT>> round_a;
        std::vector<pb_linear_combination_array<FieldT>> round_b;
        std::vector<pb_linear_combination_array<FieldT>> round_c;
        std::vector<pb_linear_combination_array<FieldT>> round_d;
        std::vector<pb_linear_combination_array<FieldT>> round_e;
        std::vector<pb_linear_combination_array<FieldT>> round_f;
        std::vector<pb_linear_combination_array<FieldT>> round_g;
        std::vector<pb_linear_combination_array<FieldT>> round_h;

        pb_variable_array<FieldT> packed_W;
        pb_variable_array<FieldT> packed_W_extended;
        std::shared_ptr<sm3_message_schedule_gadget<FieldT>> message_schedule;
        std::vector<sm3_round_function_gadget<FieldT>> round_functions;

        std::vector<parity_gadget<FieldT>> compute_output;

    public:
        pb_linear_combination_array<FieldT> prev_output;
        pb_variable_array<FieldT> new_block;
        digest_variable<FieldT> output;

        sm3_compression_function_gadget(protoboard<FieldT> &pb,
                                        const pb_linear_combination_array<FieldT> &prev_output,
                                        const pb_variable_array<FieldT> &new_block,
                                        const digest_variable<FieldT> &output,
                                        const std::string &annotation_prefix);
        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };

    template <typename FieldT>
    class sm3_two_to_one_hash_gadget : public gadget<FieldT>
    {
    public:
        typedef libff::bit_vector hash_value_type;
        typedef merkle_authentication_path merkle_authentication_path_type;

        std::shared_ptr<sm3_compression_function_gadget<FieldT>> f;

        sm3_two_to_one_hash_gadget(protoboard<FieldT> &pb,
                                   const digest_variable<FieldT> &left,
                                   const digest_variable<FieldT> &right,
                                   const digest_variable<FieldT> &output,
                                   const std::string &annotation_prefix);
        sm3_two_to_one_hash_gadget(protoboard<FieldT> &pb,
                                   const size_t block_length,
                                   const block_variable<FieldT> &input_block,
                                   const digest_variable<FieldT> &output,
                                   const std::string &annotation_prefix);

        void generate_r1cs_constraints(const bool ensure_output_bitness = true);
        void generate_r1cs_witness();

        static size_t get_block_len();
        static size_t get_digest_len();
        static libff::bit_vector get_hash(const libff::bit_vector &input);

        static size_t expected_constraints(const bool ensure_output_bitness = true);
    };
} // libsnark

#include <src/sm3/sm3_gadget.tcc>

#endif // SM3_GADGET_HPP_
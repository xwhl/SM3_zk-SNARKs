#ifndef SM3_COMPONENTS_HPP_
#define SM3_COMPONENTS_HPP_

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <src/sm3/sm3_aux.hpp>

namespace libsnark
{
    const size_t sm3_digest_size = 256;
    const size_t sm3_block_size = 512;

    template <typename FieldT>
    pb_linear_combination_array<FieldT> sm3_default_IV(protoboard<FieldT> &pb);

    template <typename FieldT>
    class sm3_message_schedule_gadget : public gadget<FieldT>
    {
    public:
        std::vector<pb_variable_array<FieldT>> W_bits;
        std::vector<pb_variable_array<FieldT>> W_extended_bits;
        std::vector<std::shared_ptr<packing_gadget<FieldT>>> pack_W;
        std::vector<std::shared_ptr<packing_gadget<FieldT>>> pack_W_extended;

        std::vector<pb_variable<FieldT>> sigma0;
        std::vector<pb_variable<FieldT>> sigma1;
        std::vector<std::shared_ptr<small_sigma_gadget<FieldT>>> compute_sigma0;
        std::vector<std::shared_ptr<small_sigma_gadget<FieldT>>> compute_sigma1;

    public:
        pb_variable_array<FieldT> M;
        pb_variable_array<FieldT> packed_W;
        pb_variable_array<FieldT> packed_W_extended;
        sm3_message_schedule_gadget(protoboard<FieldT> &pb,
                                    const pb_variable_array<FieldT> &M,
                                    const pb_variable_array<FieldT> &packed_W,
                                    const pb_variable_array<FieldT> &packed_W_extended,
                                    const std::string &annotation_prefix);
        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };

    template <typename FieldT>
    class sm3_round_function_gadget : public gadget<FieldT>
    {
    public:
        pb_variable<FieldT> sigma0;
        pb_variable<FieldT> sigma1;
        std::shared_ptr<big_sigma_gadget<FieldT>> compute_sigma0;
        std::shared_ptr<big_sigma_gadget<FieldT>> compute_sigma1;
        pb_variable<FieldT> choice;
        pb_variable<FieldT> majority;
        std::shared_ptr<choice_gadget<FieldT>> compute_choice;
        std::shared_ptr<majority_gadget<FieldT>> compute_majority;
        pb_variable<FieldT> packed_d;
        std::shared_ptr<packing_gadget<FieldT>> pack_d;
        pb_variable<FieldT> packed_h;
        std::shared_ptr<packing_gadget<FieldT>> pack_h;
        pb_variable<FieldT> unreduced_new_a;
        pb_variable<FieldT> unreduced_new_e;
        std::shared_ptr<lastbits_gadget<FieldT>> mod_reduce_new_a;
        std::shared_ptr<lastbits_gadget<FieldT>> mod_reduce_new_e;
        pb_variable<FieldT> packed_new_a;
        pb_variable<FieldT> packed_new_e;

    public:
        pb_linear_combination_array<FieldT> a;
        pb_linear_combination_array<FieldT> b;
        pb_linear_combination_array<FieldT> c;
        pb_linear_combination_array<FieldT> d;
        pb_linear_combination_array<FieldT> e;
        pb_linear_combination_array<FieldT> f;
        pb_linear_combination_array<FieldT> g;
        pb_linear_combination_array<FieldT> h;
        pb_variable<FieldT> W;
        pb_variable<FieldT> W_extended;
        size_t i;
        pb_linear_combination_array<FieldT> new_a;
        pb_linear_combination_array<FieldT> new_e;

        sm3_round_function_gadget(protoboard<FieldT> &pb,
                                  const pb_linear_combination_array<FieldT> &a,
                                  const pb_linear_combination_array<FieldT> &b,
                                  const pb_linear_combination_array<FieldT> &c,
                                  const pb_linear_combination_array<FieldT> &d,
                                  const pb_linear_combination_array<FieldT> &e,
                                  const pb_linear_combination_array<FieldT> &f,
                                  const pb_linear_combination_array<FieldT> &g,
                                  const pb_linear_combination_array<FieldT> &h,
                                  const pb_variable<FieldT> &W,
                                  const pb_variable<FieldT> &W_extended,
                                  const pb_linear_combination_array<FieldT> &new_a,
                                  const pb_linear_combination_array<FieldT> &new_e,
                                  const size_t i,
                                  const std::string &annotation_prefix);

        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };
} // libsnark

#include <src/sm3/sm3_components.tcc>

#endif // SM3_COMPONENTS_HPP_
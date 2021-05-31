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
        // W_0~67
        std::vector<pb_variable_array<FieldT>> W_bits;
        // W'_0~63
        std::vector<pb_variable_array<FieldT>> W_extended_bits;
        // Wj−16 ⊕ Wj−9 ⊕ (Wj−3 ≪ 15)
        std::vector<pb_variable_array<FieldT>> p1_input;
        // P_1(p1_input)
        std::vector<pb_variable_array<FieldT>> p1;

        // compute W_16~67
        std::vector<std::shared_ptr<permutation_gadget<FieldT>>> compute_W;
        // compute W'_0~63
        std::vector<std::shared_ptr<permutation_gadget<FieldT>>> compute_W_extended;
        std::vector<std::shared_ptr<parity_gadget<FieldT>>> compute_p1_input;
        std::vector<std::shared_ptr<permutation_gadget<FieldT>>> compute_p1;

        // for addition in round functions.
        std::vector<std::shared_ptr<packing_gadget<FieldT>>> pack_W;
        std::vector<std::shared_ptr<packing_gadget<FieldT>>> pack_W_extended;

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
        pb_variable<FieldT> packed_e;
        std::shared_ptr<packing_gadget<FieldT>> pack_e;
        pb_variable<FieldT> packed_d;
        std::shared_ptr<packing_gadget<FieldT>> pack_d;
        pb_variable<FieldT> packed_h;
        std::shared_ptr<packing_gadget<FieldT>> pack_h;

        pb_variable<FieldT> a_rotl_packed;
        pb_variable_array<FieldT> a_rotl_bits;
        std::shared_ptr<packing_gadget<FieldT>> pack_a_rotl;

        pb_variable<FieldT> ss1_unreduced;
        pb_variable<FieldT> ss1_packed;
        pb_variable_array<FieldT> ss1_bits;
        std::shared_ptr<lastbits_gadget<FieldT>> mod_reduce_ss1;
        pb_variable_array<FieldT> ss1_rotl_bits;
        pb_variable<FieldT> ss1_rotl_packed;

        pb_variable<FieldT> ss2_packed;
        pb_variable_array<FieldT> ss2_bits;
        std::shared_ptr<parity_gadget<FieldT>> compute_ss2;
        std::shared_ptr<packing_gadget<FieldT>> pack_ss2;

        pb_variable<FieldT> ff;
        std::shared_ptr<ff_gadget<FieldT>> compute_ff;

        pb_variable<FieldT> unreduced_new_a;
        std::shared_ptr<lastbits_gadget<FieldT>> mod_reduce_new_a;
        pb_variable<FieldT> packed_new_a;

        pb_variable<FieldT> gg;
        std::shared_ptr<ff_gadget<FieldT>> compute_gg;

        pb_variable<FieldT> tt2_unreduced;
        pb_variable<FieldT> tt2_packed;
        pb_variable_array<FieldT> tt2_bits;
        std::shared_ptr<lastbits_gadget<FieldT>> mod_reduce_tt2;

        std::shared_ptr<permutation_gadget<FieldT>> compute_new_e;

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
        unsigned long T;
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
                                  const unsigned long T,
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
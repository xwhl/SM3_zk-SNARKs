// https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
#ifndef SM3_AUX_HPP_
#define SM3_AUX_HPP_

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_aux.hpp>

namespace libsnark
{
    // lastbits_gadget, XOR3_gadget, choice_gadget, majority_gadget were defined in sha256_gadget

    // XOR3: a xor b xor c (bit)
    // choice_gadget: ( X ∧ Y ) ∨ ( ¬ X ∧ Z) is equivalent to  ( X ∧ Y ) ⊕ ( ¬ X ∧ Z)
    // majority_gadget: (X ∧ Y) ∨ (X ∧ Z) ∨ (Y ∧ Z) is equivalent to (X ∧ Y) ⊕ (X ∧ Z) ⊕ (Y ∧ Z)

    //FF consists of parity and majority gadget;
    //GG consists of parity and choice gadget;
    //choice and majority gadgets output packed result, parity and permutation gadget outputs bits result witch will be packed when needed(in round function or P0).

    // X ⊕ Y ⊕ Z
    template <typename FieldT>
    class parity_gadget : public gadget<FieldT>
    {
    public:
        pb_linear_combination_array<FieldT> X;
        pb_linear_combination_array<FieldT> Y;
        pb_linear_combination_array<FieldT> Z;
        std::vector<std::shared_ptr<XOR3_gadget<FieldT>>> compute_bits;
        pb_variable_array<FieldT> result_bits;
        protoboard<FieldT> pb;

        parity_gadget(protoboard<FieldT> &pb,
                      const pb_linear_combination_array<FieldT> &X,
                      const pb_linear_combination_array<FieldT> &Y,
                      const pb_linear_combination_array<FieldT> &Z,
                      const bool assume_Z_is_zero,
                      const size_t rot1,
                      const size_t rot2,
                      const size_t rot3,
                      const pb_variable_array<FieldT> &result_bits,
                      const std::string &annotation_prefix);

        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };

    // X<<<rot1 ⊕ X<<<rot2 ⊕ X<<<rot3
    template <typename FieldT>
    class permutation_gadget : public gadget<FieldT>
    {
    private:
        pb_linear_combination_array<FieldT> X;

    public:
        pb_linear_combination_array<FieldT> result_bits;
        std::vector<std::shared_ptr<XOR3_gadget<FieldT>>> compute_bits;

        permutation_gadget(
            protoboard<FieldT> &pb,
            const pb_linear_combination_array<FieldT> &X,
            const pb_linear_combination_array<FieldT> &result_bits,
            const size_t rot1,
            const size_t rot2,
            const size_t rot3,
            const std::string &annotation_prefix);

        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };

    template <typename FieldT>
    class ff_gadget : public gadget<FieldT>
    {
    private:
        pb_variable_array<FieldT> result_bits;

    public:
        pb_variable<FieldT> result;
        size_t i;
        std::shared_ptr<parity_gadget<FieldT>> parity;
        std::shared_ptr<majority_gadget<FieldT>> majority;
        std::shared_ptr<packing_gadget<FieldT>> pack_parity_result;

        ff_gadget(protoboard<FieldT> &pb,
                  const pb_linear_combination_array<FieldT> &X,
                  const pb_linear_combination_array<FieldT> &Y,
                  const pb_linear_combination_array<FieldT> &Z,
                  const size_t i,
                  const pb_variable<FieldT> &result, const std::string &annotation_prefix);

        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };

    template <typename FieldT>
    class gg_gadget : public gadget<FieldT>
    {
    private:
        pb_variable_array<FieldT> result_bits;

    public:
        pb_variable<FieldT> result;
        size_t i;
        std::shared_ptr<parity_gadget<FieldT>> parity;
        std::shared_ptr<choice_gadget<FieldT>> choice;
        std::shared_ptr<packing_gadget<FieldT>> pack_parity_result;

        gg_gadget(protoboard<FieldT> &pb,
                  const pb_linear_combination_array<FieldT> &X,
                  const pb_linear_combination_array<FieldT> &Y,
                  const pb_linear_combination_array<FieldT> &Z,
                  const size_t i,
                  const pb_variable<FieldT> &result, const std::string &annotation_prefix);

        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };

    // X <<< rot
    template <typename FieldT>
    pb_linear_combination_array<FieldT> rotate_left(const pb_linear_combination_array<FieldT> &pre, size_t rot);

} // libsnark

#include <src/sm3/sm3_aux.tcc>

#endif // SM3_AUX_HPP_
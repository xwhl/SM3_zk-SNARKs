// https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
#ifndef SM3_AUX_HPP_
#define SM3_AUX_HPP_

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

namespace libsnark
{

    template <typename FieldT>
    class lastbits_gadget : public gadget<FieldT>
    {
    public:
        pb_variable<FieldT> X;
        size_t X_bits;
        pb_variable<FieldT> result;
        pb_linear_combination_array<FieldT> result_bits;

        pb_linear_combination_array<FieldT> full_bits;
        std::shared_ptr<packing_gadget<FieldT>> unpack_bits;
        std::shared_ptr<packing_gadget<FieldT>> pack_result;

        lastbits_gadget(protoboard<FieldT> &pb,
                        const pb_variable<FieldT> &X,
                        const size_t X_bits,
                        const pb_variable<FieldT> &result,
                        const pb_linear_combination_array<FieldT> &result_bits,
                        const std::string &annotation_prefix);

        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };

    // a xor b xor c (bit)
    template <typename FieldT>
    class XOR3_gadget : public gadget<FieldT>
    {
    private:
        pb_variable<FieldT> tmp;

    public:
        pb_linear_combination<FieldT> A;
        pb_linear_combination<FieldT> B;
        pb_linear_combination<FieldT> C;
        bool assume_C_is_zero;
        pb_linear_combination<FieldT> out;

        XOR3_gadget(protoboard<FieldT> &pb,
                    const pb_linear_combination<FieldT> &A,
                    const pb_linear_combination<FieldT> &B,
                    const pb_linear_combination<FieldT> &C,
                    const bool assume_C_is_zero,
                    const pb_linear_combination<FieldT> &out,
                    const std::string &annotation_prefix);

        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };

    //FF consists of parity and majority gadget;
    //GG consists of parity and choice gadget;
    //choice and majority gadgets output packed result, parity and permutation gadget outputs bits result witch will be packed when needed(in round function or P0).

    // ( X ∧ Y ) ∨ ( ¬ X ∧ Z) is equivalent to  ( X ∧ Y ) ⊕ ( ¬ X ∧ Z)
    template <typename FieldT>
    class choice_gadget : public gadget<FieldT>
    {
    private:
        pb_variable_array<FieldT> result_bits;

    public:
        pb_linear_combination_array<FieldT> X;
        pb_linear_combination_array<FieldT> Y;
        pb_linear_combination_array<FieldT> Z;
        pb_variable<FieldT> result;
        std::shared_ptr<packing_gadget<FieldT>> pack_result;

        choice_gadget(protoboard<FieldT> &pb,
                      const pb_linear_combination_array<FieldT> &X,
                      const pb_linear_combination_array<FieldT> &Y,
                      const pb_linear_combination_array<FieldT> &Z,
                      const pb_variable<FieldT> &result, const std::string &annotation_prefix);

        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };

    // (X ∧ Y) ∨ (X ∧ Z) ∨ (Y ∧ Z) is equivalent to (X ∧ Y) ⊕ (X ∧ Z) ⊕ (Y ∧ Z)
    template <typename FieldT>
    class majority_gadget : public gadget<FieldT>
    {
    private:
        pb_variable_array<FieldT> result_bits;
        std::shared_ptr<packing_gadget<FieldT>> pack_result;

    public:
        pb_linear_combination_array<FieldT> X;
        pb_linear_combination_array<FieldT> Y;
        pb_linear_combination_array<FieldT> Z;
        pb_variable<FieldT> result;

        majority_gadget(protoboard<FieldT> &pb,
                        const pb_linear_combination_array<FieldT> &X,
                        const pb_linear_combination_array<FieldT> &Y,
                        const pb_linear_combination_array<FieldT> &Z,
                        const pb_variable<FieldT> &result,
                        const std::string &annotation_prefix);

        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };

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
        pb_variable_array<FieldT> result_bits;
        std::vector<std::shared_ptr<XOR3_gadget<FieldT>>> compute_bits;

        permutation_gadget(
            protoboard<FieldT> &pb,
            const pb_linear_combination_array<FieldT> &X,
            const pb_variable_array<FieldT> &result_bits,
            const size_t rot1,
            const size_t rot2,
            const size_t rot3,
            const std::string &annotation_prefix);

        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };

    // X <<< rot
    template <typename FieldT>
    pb_variable_array<FieldT> rotate_left(const pb_variable_array<FieldT> &pre, const std::string &annotation = "");

} // libsnark

#include <src/sm3/sm3_aux.tcc>

#endif // SM3_AUX_HPP_